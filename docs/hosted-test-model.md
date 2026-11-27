# Hosted test model (test stack only)

The model papAIa ships runs inside the stack. LiteLLM may route to a model hosted outside the
stack only in a **test stack**, with **synthetic data only**. Everywhere else the render
refuses such a route.

## Production installations: no route outside the stack

On every `setup`, `start` and `addon` operation `papaia-ctl` renders
`$PAPAIA_CONFIG_DIR/ai/litellm/config.yaml` from the repository base, the profile and add-on
fragments and the operator overlay. Without the test switch the render stops when any entry of
`model_list`, from whichever layer, leaves the stack. An entry stays inside the stack only when
all of these hold:

- its provider sends to `api_base` and nowhere else: `openai/`, `text-completion-openai/`,
  `hosted_vllm/`, `ollama/` or `ollama_chat/` (as the prefix of `model` or as
  `custom_llm_provider`);
- `litellm_params` names no other endpoint: no `base_url`, no `*_url`, `*_endpoint`, `*_base`,
  no `aws_*`, `vertex_*`, `azure_*`, `api_version`, region, location or project key, and no
  `litellm_credential_name` (a credential brings its own `api_base` and key);
- `api_base` addresses a service the rendered stack defines, or the native LocalAI of this host
  (`LOCALAI_RUNTIME=native`, the exact address the render generates).

The services the stack defines are the core compose services without a profile or with an
active profile (`COMPOSE_PROFILES`), the services of the active add-ons, and their
`container_name` and network aliases. Any other short name is refused: Docker's DNS forwards
it to the host's resolver and its search domains, which may answer with a host outside the
stack.

| `litellm_params.api_base` of the entry | Inside the stack? |
|---|---|
| a service of the stack (`http://localai:8080/v1`, `http://speaches:8000/v1` with the voice profile on) | yes |
| the native LocalAI of this host | yes |
| a short name the stack does not define (`http://intranet-llm:8000/v1`) | no |
| a name with a domain, an IP address in any notation (`https://api.example.org/v1`, `http://203.0.113.5/v1`, `http://3627734862/v1`, `http://0xd83ad6ce/v1`) | no |
| a URL with user information, a backslash, white space or control characters, or one `urlsplit` does not give back unchanged | no |
| taken from the environment (`os.environ/...`) | no, the target is unknown |
| missing (the provider's own endpoint) | no |

The message names the model entries and the switch:

```
ai/litellm/config.yaml: model(s) 'test-hosted-chat' route outside the stack. A hosted model is
allowed only in the test stack (PAPAIA_TEST_EXTERNAL_MODEL=1 in $PAPAIA_CONFIG_DIR/.env); the
shipped model stays local
```

The render decides which entries are test backends; a `model_info.test_backend` written in a
layer is removed.

Two top-level keys of the configuration stop the render as well, with or without the switch:

- a non-empty `credential_list`: a credential can carry its own `api_base` and `api_key`, which
  an entry would use instead of the checked ones, and its key would sit in the rendered file;
- `environment_variables` that set `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` or `ALL_PROXY`, in
  any spelling: LiteLLM exports them into its process and would empty the proxy of the test
  stack. Other `environment_variables` stay.

Models registered in the LiteLLM Admin UI are stored in its database and do not pass through
the render (`store_model_in_db: true` stays on), so this check does not cover them, and a key
entered there sits in the database volume, which the volume backups carry. Register models
through the overlay instead. Closing this path is an open requirement (see Limits).

## The test stack

The switch is the root variable `PAPAIA_TEST_EXTERNAL_MODEL` in `$PAPAIA_CONFIG_DIR/.env`. Only the
exact value `1` turns it on. Set it only on an installation that holds synthetic data, never on
one with real data.

1. Put the key into `$PAPAIA_CONFIG_DIR/ai/litellm/test-hosted.env` with mode 0600:

   ```sh
   umask 077
   printf 'TEST_HOSTED_API_KEY=%s\n' "<key>" > "$PAPAIA_CONFIG_DIR/ai/litellm/test-hosted.env"
   ```

2. Add the route to the overlay `$PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml`:

   ```yaml
   model_list:
     - model_name: test-hosted-chat
       litellm_params:
         model: openai/<model id>
         api_base: https://<host of the provider>/v1
         api_key: os.environ/TEST_HOSTED_API_KEY
   ```

3. Set `PAPAIA_TEST_EXTERNAL_MODEL=1` in `$PAPAIA_CONFIG_DIR/.env` and recreate LiteLLM so it picks
   up the new networks and variables: `papaia-ctl stop --clean-up --profiles=litellm`, then
   `papaia-ctl start`.

With the switch on, the render still stops unless

- every hosted entry uses a provider that sends to `api_base` only, as listed above; a
  provider such as `vertex_ai/` or `bedrock/` can take its endpoint from region or project
  variables instead;
- every hosted entry names its endpoint as an `https://host[:port]/path` URL in `api_base` (no
  user information, no query or fragment, no `os.environ/...`), so the exit can allow exactly
  that host and no key sits in the URL;
- no hosted entry names another endpoint (`base_url`, `aws_*`, `vertex_*`, `azure_*`,
  `litellm_credential_name`, ...);
- every hosted entry names its key as `os.environ/TEST_HOSTED_<NAME>` (upper case), never the
  key itself. The prefix keeps out the variables the LiteLLM container sets itself, such as
  `DATABASE_URL` with the database password, which would otherwise go to the hosted host as the
  bearer;
- all hosted entries share **one** host and port;
- `ai/litellm/test-hosted.env` is a regular file (not a symbolic link), belongs to the user who
  runs `papaia-ctl` or owns the configuration directory, has mode 0600, sets each referenced
  variable and nothing else (it is an env file of the container, so any other variable would
  change LiteLLM's settings);
- no `<VAR>` has a value in `ai/litellm/.env`, which every backup carries;
- the installation runs on a single host (not a distributed installation).

The messages never repeat the value of `api_key`.

### What the render does with the switch on

- Each hosted entry gets `model_info.test_backend: true` in the rendered configuration.
- `papaia-egress` gets one more source, `litellm`, whose allow list is the one host and port
  ([egress.md](egress.md)). Each connection is one `papaia.audit/1` line of the exit.
- The override `$PAPAIA_CONFIG_DIR/overrides/docker-compose.litellm.hosted-model.override.yml`
  puts LiteLLM on the internal network `<project>-litellm-egress`, where `papaia-egress` answers
  as `egress-litellm:3128`, sets `HTTPS_PROXY` and `HTTP_PROXY` to it, lists in `NO_PROXY` the
  model services inside the stack and the host of LiteLLM's login (`GENERIC_TOKEN_ENDPOINT`,
  `GENERIC_USERINFO_ENDPOINT`, only where they point at the identity provider of the root
  `.env`: `OIDC_ISSUER` or `OIDC_TOKEN_URL`), and loads `ai/litellm/test-hosted.env` as an
  extra env file of the container.
- An add-on named `litellm` with an egress network stops the render while the switch is on;
  the source name belongs to the gateway.

Switching back: remove the route from the overlay, empty `PAPAIA_TEST_EXTERNAL_MODEL`, delete
`ai/litellm/test-hosted.env` and recreate LiteLLM as in step 3. The next render removes the
source and the override. Revoke the key with the provider after the run.

### The key and the backups

`papaia-ctl backup` archives the configuration directory without
`ai/litellm/test-hosted.env`, on a single host and in a distributed installation alike. After a
restore the file is missing, and the render asks for it again while the switch is on. Keep
the backups of a test stack encrypted all the same and delete them after the run.

## Limits

The render rule is the control this repository enforces. The following is not closed by it:

- **The exit depends on LiteLLM honouring the proxy variables.** LiteLLM stays on
  `papaia-net` as well, which has a route to the outside. Whether LiteLLM 1.110.2 sends its
  provider calls through `HTTPS_PROXY`/`HTTP_PROXY` is not verified yet; every name in
  `NO_PROXY` and every client that ignores the variables goes out directly. The one-host limit
  at `papaia-egress` holds only as far as the variables are honoured. The hard control is a host
  rule (`DOCKER-USER`, PLT-62-A1-Z) or an internal core network, both outside this change.
- **Models in the LiteLLM database.** A model registered in the Admin UI bypasses the render,
  with or without the switch. Until this path is closed (rendered `store_model_in_db: false`,
  or a check of the database models), PLT-62-A1 cannot be claimed for the model gateway.
- **Other outbound settings of LiteLLM.** Besides `model_list`, `credential_list` and the
  proxy variables in `environment_variables`, the check reads no key of the configuration. An
  overlay can still open other routes out in the same file, among them:
  - `litellm_settings.success_callback`, `failure_callback` or `callbacks` to hosted logging
    services, and `general_settings.alerting` webhooks;
  - `general_settings.pass_through_endpoints`, which forward requests to any target;
  - `guardrails` with an `api_base` of their own;
  - `mcp_servers` with URLs;
  - a cache host (`litellm_settings.cache_params`, a Redis host);
  - further `environment_variables` that change where LiteLLM or its libraries send.

  Review those keys in an overlay by hand. Closing them is an open requirement.
- **The rendered file is not the control.** The render checks the merged configuration before
  it writes it. The allow list of the exit and the override are derived from the rendered file
  again and classify each entry against the services of the stack, so a hand edit of the
  rendered file cannot add a model service inside the stack; it can still change everything
  else until the next render overwrites it.
- **Start-up calls.** LiteLLM reads its model cost map from the image
  (`LITELLM_LOCAL_MODEL_COST_MAP=True` in its compose file); without it, it fetches the map from
  the internet at every start. Whether 1.110.2 makes other calls at start-up (telemetry,
  version checks) is not verified; a capture during the smoke test has to show it.
- The banner "Testbetrieb mit externem Modell" in the frames of the modules reads the same
  switch; it is not part of this repository.
