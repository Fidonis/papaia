# Deletions for the core start gate (papaia-replay)

After a restored snapshot, `papaia-lifecycle` replays the erasure journal before the edge
opens ([lifecycle.md](lifecycle.md#core-start-gate)). The identity steps it does itself.
Chat (LibreChat) and model gateway (LiteLLM) are deleted in by `papaia-replay`: the
container of `papaia-lifecycle` holds `manage-users` of the identity provider and gets no
access to the chat database or the gateway's management API as well.

`papaia-replay` is part of the profile `lifecycle` and has no other function.

## Requests

One endpoint, `POST https://papaia-replay:8443/replay`, over mutual TLS. The server
certificate comes from the platform PKI (`src/infra/replay/pki.yaml`). Only the client
certificate `CN=papaia-lifecycle` of the same CA is answered. Any other certificate of the
CA gets `403` and a `denied` audit row. A caller without a certificate gets no
connection. The body is one of three fixed forms. Unknown or missing fields, another
kind, duplicate keys and more than 1024 bytes are refused with `400`:

| `kind` | Fields | Deletes |
|---|---|---|
| `erase_subject` | `sub` (`A-Z a-z 0-9 -`, 1 to 64) | the person's gateway usage, then her chat account with every object filed under it |
| `chat_sessions_reset` | none | every stored chat session of every account (a restored database holds sessions that were ended) |
| `key_revoke` | `key_id` (the id the gateway stores, never the key) | that gateway key |

The answer is `{"counts": {name: number}}`, for example `chat_conversations`,
`chat_messages`, `chat_accounts`, `gateway_end_users`, `gateway_keys`. It holds no content
and no account data. A backend that fails gives `502` with `{"error": "backend_failed"}`;
`papaia-lifecycle` keeps that part of the gate closed and repeats the job
(`CORE-STARTGATE-REPLAY-FAILED`). Every job can be repeated: a second run finds nothing
and counts 0. Jobs run one after the other, never in parallel.

`papaia-lifecycle` resolves `subject_ref` of a journal entry to the `sub` through the
accounts of the identity provider and sends the `sub`. `papaia-replay` never holds the
installation key `erasure-hmac`.

## Chat

The chat database is reached on `papaia-replay-chat-net` (internal, the database and
`papaia-replay` alone) with the fixed role `papaia-replay-chat`. `papaia-ctl start`
creates or updates the role and its login after `up` (`replay-chat-sync`), inside the
running database container. The password goes in on stdin, never on a command line. The
role may `find` and `remove` in these collections of the database `LibreChat` and nothing
else, no role or user administration and no other database:

`users`, `conversations`, `messages`, `files`, `presets`, `prompts`, `promptgroups`,
`sharedlinks`, `conversationtags`, `toolcalls`, `memoryentries`, `pluginauths`, `keys`,
`balances`, `transactions`, `tokens`, `sessions`.

For `erase_subject` the service reads the `_id` of the accounts whose `openidId` is the
`sub`, and nothing else. It then removes, in that order, every document of the
collections above filed under one of those ids (as an object id or as its string), and
the accounts last. A run that fails half-way finds the account again when it is repeated.
The service signs in with SCRAM-SHA-256 through its own minimal client of the database's
wire protocol (Python standard library, no driver).

**Not covered by this version.** Uploaded files on the chat's file volumes and the chat's
search index (`librechat-meilisearch`) are not touched: the documents in the database go,
the stored file bytes and the index entries of the person's messages stay until LibreChat
or the operator removes them. Shared assistants a person built in the chat are kept,
since others may use them.

## Model gateway

The gateway is reached on `papaia-replay-gw-net` (internal, `litellm` and `papaia-replay`
alone) at `http://litellm:4000`, with three routes only. Anything else is refused before
it is sent:

| Route | For |
|---|---|
| `GET /customer/info?end_user_id=...` | is there usage of this end user (the answer is drained, not kept) |
| `POST /customer/delete` | delete the end users found: the `sub` and the person's chat account ids |
| `POST /key/delete` | `key_revoke` (`404`: the key is gone already, counts 0) |

The gateway is called before the chat account is deleted, so the chat account id is still
known.

## Its logins

`render` (every `setup` and `start`) keeps `$PAPAIA_CONFIG_DIR/security/replay/` (mode
0700), which the container mounts read-only. Each file is mode 0600 and exists only while
its profile is on:

| File | Profiles | Content |
|---|---|---|
| `chat-password` | `lifecycle`, `librechat` | the password of `papaia-replay-chat`, made once |
| `gateway-key` | `lifecycle`, `litellm` | `LITELLM_MASTER_KEY` of `ai/litellm/.env` (see residual risk) |

Without a file the service has nothing of that backend to delete and answers without its
counts. Without the profile `lifecycle` both files are removed.

## Audit

One `papaia.audit/1` line per request on the service's standard output (writer
`papaia-replay`, operation `replay.<kind>`, event `operation`, effect `delete`). The line
carries the correlation id `papaia-lifecycle` sends, `detail.kind` and `detail.counts`, and
`object_ref` names the `sub` or the key id. Refused and failed requests are rows too
(`denied` with the reason, `error` with `backend_failed`). `papaia-lifecycle` writes its own
row per job (`lifecycle.startgate_replay`). `papaia-ctl replay-chat-sync` writes
`replay_chat_role` (or `replay_chat_role_failed`) to the host's audit journal.

## Distributed installations

`papaia-replay` belongs to the profile `lifecycle` and runs with `papaia-lifecycle` on
Keycloak's node. Its three networks are networks of that node. It reaches the chat
database and the model gateway only when they run there too. Otherwise its jobs fail,
and the start gate keeps chat and gateway closed after a restored snapshot
(`CORE-STARTGATE-REPLAY-FAILED`). Placing them on other nodes needs a route between
the nodes. This version does not provide one.

## Residual risk

- **Chat database without access control.** The shipped chat database runs with
  `--noauth`. The role `papaia-replay-chat` is created and used for the sign-in, but the
  database does not enforce it. Until the chat database runs with access control, the
  boundary is the network: `papaia-replay-chat-net` reaches the database from
  `papaia-replay` alone, and LibreChat stays on its own network. Switching on access
  control for the chat database is a change of its own (LibreChat's connection string,
  an administration login, the migration of existing installations).
- **Read rights on the chat collections.** A filtered delete needs `find` next to
  `remove`, so the role may read the collections it deletes in. The service reads only
  account ids. This read right is a named residual risk (sicherheit §3.3).
- **Master key of the gateway.** No route-restricted management key of the pinned gateway
  has been verified yet, so `papaia-replay` holds the master key. Whoever controls the
  container can use every management route of the gateway. Measures: one network,
  shared with `litellm` alone; the service calls three routes and refuses every other
  path in its own code; the key is a file in a read-only mount; every call is part of an
  audited job. The call goes over plain HTTP on that internal network.
- **Usage rows of the spend log.** The gateway's per-request spend-log rows name the key
  and, where a caller sent `user`, that value. Only the end-user records are deleted
  here. The spend-log rows keep counts, never content, and age out with the gateway's
  retention.
