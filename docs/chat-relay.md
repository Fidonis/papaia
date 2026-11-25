# Chat relay

`papaia-chat-relay` is the only way from the chat to a tool server outside the suite
(`trust: addon` in the platform catalog). LibreChat sends every tool server the signed-in
person's access token, and that token carries the audience of every suite server the chat
calls; a server outside the suite must never receive it. The relay takes that token,
exchanges it at the identity provider for a token with exactly the add-on's audience and
forwards the call with the exchanged token. The decision, the alternatives and the
security assessment are in
[ADR 0029](adr/0029-reach-a-tool-server-outside-the-suite-through-a-core-chat-relay.md).

The relay is part of the profile `librechat` and runs the core's own image
`ghcr.io/fidonis/papaia-chat-relay` (one standard-library Python file,
`src/infra/chat-relay/relay.py`). Without an allowed add-on it refuses every call.

## The path of one call

```
LibreChat ──(chat token: aud ∋ papaia-chat-relay, azp librechat)──▶ papaia-chat-relay
papaia-chat-relay ──(token exchange, scope=aud-<audience>)──▶ Keycloak
papaia-chat-relay ──(exchanged token: aud = <audience>, azp papaia-chat-relay)──▶ add-on
```

```
POST http://papaia-chat-relay:8080/servers/<audience>/mcp
Authorization: Bearer <the person's chat token>
Content-Type: application/json
X-Papaia-Correlation-Id: <optional, 1 to 64 of A-Z a-z 0-9 ->
```

| Step | Rule |
|---|---|
| Chat token | Signed with one of the realm's keys (RS256 only), issuer `OIDC_ISSUER`, not expired (30 s clock skew), `aud` contains `papaia-chat-relay`. A bad, foreign, unsigned or expired token: 401 `token_invalid`, no audit row (it names nobody). `azp` other than `librechat`, or a token without a session (`sid`, a service account): 403 `token_invalid` with an audit row. |
| Target | Only an audience on the relay's list (`servers.json`, below). Any other audience, the relay itself, or a missing or malformed list: 403 `not_allowed`, before any exchange. |
| Methods | `initialize`, `ping` and `tools/list` are answered by the relay itself; `notifications/initialized` and `notifications/cancelled` are acknowledged (202). `tools/list` lists exactly the tools of the list, with their title, description and `input_schema`, so the add-on cannot change what the model sees. Every other method (resources, prompts, sampling, elicitation, roots, batches) is refused, and unknown fields of the JSON-RPC envelope are refused. |
| Tool call | The tool must be on the list (`tool_not_declared`) and its arguments must match the declared `input_schema` (`invalid_arguments`); both are checked before any token is exchanged. A schema keyword the relay does not check (for example `$ref`) fails closed. |
| Exchange | RFC 8693 at `https://keycloak:8443/realms/papaia/protocol/openid-connect/token` as the client `papaia-chat-relay` with `private_key_jwt` (ES256): `subject_token` the chat token, `requested_token_type` access token, `scope` exactly the one `aud-<audience>` scope of the list (built with the kit's `exchange_scope`). The answer must be one Bearer access token without a refresh token; the token must check against the realm's keys and carry exactly the target as `aud`, `papaia-chat-relay` as `azp`, the person's `sub` and at most 300 s of lifetime. Anything else: `exchange_refused`; no answer: `idp_unavailable`. |
| Forwarding | To the address of the list, with `Authorization: Bearer <exchanged token>` and `X-Papaia-Correlation-Id`, nothing else of the incoming request. One MCP session per call (`initialize`, `notifications/initialized`, `tools/call`, closed afterwards); JSON or event-stream answers. No redirect is followed, no proxy is used. |
| Limits | Request body 1 MiB (413), answer of the add-on 8 MiB (`response_too_large`), 60 s per call (`upstream_timeout`), 60 requests per minute per person and add-on (429 `rate_limited` with `Retry-After`), at most 128 requests at a time (503 `busy` with `Retry-After`). The 60 s hold for the whole call, however slowly the add-on sends its headers or body: at the deadline the relay shuts the connection down. The token endpoint and the key set get 10 s the same way, the closing `DELETE` at most 5 s within the call's 60 s. Nothing is retried. |
| Failure | Every failure ends the call with a JSON-RPC error whose `data.error_code` names the reason. Nothing falls back to a direct call or to the chat token. |

The relay keeps no token beyond the call it serves: no cache, no file, no log line.

## The list of allowed servers

`$PAPAIA_CONFIG_DIR/chat-relay/servers.json`, mounted read-only into the relay alone and
read again when it changes. The core writes it when the operator allows an add-on for the
chat (the opt-in commands that write it, and the chat's entries for the relayed servers,
are not part of this release yet); `papaia-ctl start` creates the empty folder. Format `papaia.chat-relay-servers/1`,
every field required, unknown fields refused, at most 12 servers:

```json
{
  "format": "papaia.chat-relay-servers/1",
  "servers": [
    {
      "audience": "mcp-paperless",
      "scope": "aud-mcp-paperless",
      "addon": "paperless-connect",
      "catalog_id": "paperless-connect.mcp",
      "address": "http://paperless-connect:8000/mcp",
      "data_class_max": "confidential",
      "tools": [
        {
          "name": "search_documents",
          "title": "Search documents",
          "description": "Full text search over the documents the person may read.",
          "input_schema": {"type": "object", "properties": {"query": {"type": "string"}},
                           "required": ["query"], "additionalProperties": false},
          "effect": "read",
          "data_class_max": "confidential"
        }
      ]
    }
  ]
}
```

Address, audience, scope and tools come from the add-on's catalog entry, never from a
request. A list that does not check makes the relay refuse every call (stderr names the
reason).

## Identity provider

The realm sync (`papaia-ctl realm sync`) keeps, while at least one opt-in is confirmed
(a pairing of `papaia-chat-relay` with an add-on's audience in
`security/pairings.yaml`):

- the client `papaia-chat-relay` (owner `papaia`): token exchange on, no refresh token for
  an exchange, `fullScopeAllowed: false`, no sign-in of persons (no standard flow), no
  `client_credentials`, no password grant, `private_key_jwt` with the public key of
  `$PAPAIA_CONFIG_DIR/security/chat-relay/private-key.pem` (made by `papaia-ctl start`,
  0600, mounted into the relay alone), the attribute `papaia.chat-relay=true`;
- its optional scopes: exactly the `aud-*` scopes of the confirmed opt-ins, at most 12; no
  default `aud-*` scope;
- the audience mapper `papaia-chat-relay-audience` on the `librechat` client, so the chat
  token reaches the relay; no other client or scope may name the relay as an audience, and
  there is no scope `aud-papaia-chat-relay`;
- the client policy `chat-relay` (grant type token exchange and `papaia.chat-relay=true`)
  with the profile `chat-relay`: the subject token's `azp` must be `librechat`. The
  one-audience policies `papaia-one-aud-<x>-<y>` apply to the relay like to every managed
  client, so an exchange for two add-ons at once is refused by Keycloak too.

When the last opt-in goes, the next sync deletes the client, its policy and the mapper. A
pairing that names the relay with an audience served here but not by an add-on outside the
suite (a suite server, a core audience, an add-on that attaches `librechat` to one of its
networks, a server without persons) stops the sync before any write; an audience that is
not installed only waits. The relay's own audience can never be paired.

## Network

`papaia-chat-relay-net` (`internal: true`) holds `librechat` and the relay alone. The relay
reaches Keycloak and the add-ons on `papaia-net`. It publishes no port, runs as the user
that owns the configuration directory on a read-only file system without capabilities, and
no add-on may attach it (`papaia-ctl addon check` refuses such a manifest).

## Audit

Every request with a verified identity for an add-on is one `papaia.audit/1` row on
stdout (the container log): writer `papaia-chat-relay`, event `operation`, role `caller`,
`sub` the person, `azp` `librechat`, `aud` the add-on's audience, `catalog_id` the
add-on's entry, `operation` `chat_relay.tool_call` (for `tools/call`) or
`chat_relay.session` (the other methods), `object_ref` `tool`/`<add-on>/<tool>`, the
declared `effect` and `data_class_max` of the tool, `result` (`allowed`, `denied`,
`error`), `error_code` and the correlation id. A valid `X-Papaia-Correlation-Id` is kept,
sent to the add-on and returned; any other value is replaced by a new one. A row never
holds a token, the arguments or the result. A tool call is not forwarded while the stream
cannot be written (`audit_unavailable`).

## Operation

| Situation | What to check |
|---|---|
| Every call `not_allowed` | `servers.json` missing or malformed (the relay's log names the reason), or the add-on is not allowed. |
| `exchange_refused` | The relay's client or its scope is missing: run `papaia-ctl realm sync` and read its notes (`no key file`, pairing waiting for approval). |
| `idp_unavailable` | Keycloak is not reachable on `papaia-net`, or the CA bundle does not match. |
| `upstream_unavailable`, `upstream_timeout` | The add-on is stopped, not on a network the relay reaches, or slower than 60 s. |
| `busy` | 128 requests are already in progress; the chat retries after `Retry-After`. Persistent: an add-on answers slowly for many persons at once. |

With `external_oidc` the core does not manage the realm: the client, the scope
`aud-<audience>`, the mapper on the chat's client and the two policies are created there by
hand, and the relay refuses every call until the exchange answers as above.
