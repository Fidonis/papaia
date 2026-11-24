---
adr: 0029
title: Reach a tool server outside the suite through a core chat relay
status: Accepted
date: 2026-11-24
deciders:
  - WilhelmSebastian
tags:
  - chat
  - identity
  - security
  - addons
supersedes: null
superseded_by: null
---

# 0029. Reach a tool server outside the suite through a core chat relay

## Context

The chat reaches a tool server only when the server is part of the suite: `trust: platform`
in the platform catalog, which the core sets for core profiles and for the components of
`compat/suite.yaml`, never the add-on (`tools/lib/chat_servers.py`, Seam 3 in
[`architecture.md`](../architecture.md#seam-3--librechat-mcp)). The reason is the token.
LibreChat sends every tool server the signed-in person's own access token, and that one
token carries the audience of every suite server the chat calls (one audience mapper per
server on the `librechat` client). A server that receives it can present it to every other
suite server as that person. Inside the suite this is accepted: the suite's servers are
released, signed and tested together. A server outside the suite must never receive it.

Some add-ons stay outside the suite on purpose, for example one that relies on a
customer's own proxy for its sign-in and is therefore not part of the suite's acceptance.
Such an add-on has no way into the chat today. Adding it to the suite would hand it the
shared token, which is the trust rule this decision keeps.

The core already has what a narrower path needs: the names register, one exchange scope
`aud-<audience>` per audience, the realm policies that refuse a token request for two
`aud-*` scopes, pairings that grant exchange rights with a second person for writes, and
the `papaia.audit/1` outbox (ADR 0018, [`audit.md`](../audit.md)).

## Decision

**1. The relay path.** A tool server outside the suite reaches the chat only through one new
core service, `papaia-chat-relay`, and only after the operator allowed that add-on for the
chat. For every allowed add-on the core renders a chat entry named after the add-on's
audience (`mcp-<system>`) that points to the relay, `/servers/<audience>/mcp`, never to the
add-on. For each request the relay

- accepts the person's chat token (see 2) and refuses every other caller;
- looks up the target only in its rendered list of allowed servers
  (`$PAPAIA_CONFIG_DIR/chat-relay/servers.json`, mounted read-only into the relay alone): the
  address, the audience and the declared operations come from the catalog entry, never from
  the request; an audience that is not on the list is refused before any exchange;
- exchanges the chat token at the identity provider for a token with exactly one audience,
  the add-on's (OAuth 2.0 Token Exchange, RFC 8693, Keycloak's standard token exchange:
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, the chat token as
  `subject_token`, `requested_token_type=urn:ietf:params:oauth:token-type:access_token`,
  `scope=aud-<audience>` with the scope name from the vendored kit's `exchange_scope()`);
- forwards the request with `Authorization: Bearer <exchanged token>` and the correlation id,
  and nothing else of the incoming headers. The relay never forwards the chat token: not as
  a header, not in a cookie, not in the body, not in a log line.

The relay passes on the MCP methods `initialize`, `notifications/initialized`,
`notifications/cancelled`, `ping`, `tools/list` and `tools/call`; every other method, and
every request from the add-on back to the chat (sampling, elicitation, roots), is refused.
`tools/list` is answered with the operations the catalog entry declares with `via: tools`,
with the catalog's title, description and `input_schema`, so the add-on cannot change what
the model sees after the operator allowed it. A `tools/call` for an undeclared tool, or whose
arguments do not match the declared `input_schema`, is refused before any token is
exchanged. Limits: request body at most 1 MiB, response at most 8 MiB, 60 s per call,
60 calls per minute per person and add-on; the relay retries nothing.

**2. The chat token at the relay.** The relay accepts a token only when its signature
checks against the realm's keys (asymmetric algorithms only), the issuer is the realm,
it is not expired (30 s clock skew at most), `azp` is `librechat`, `aud` contains
`papaia-chat-relay` and it carries a session (`sid`, a person, never a service account).
The audience reaches the chat token through one audience mapper,
`papaia-chat-relay-audience`, on the `librechat` client. The realm sync creates it while at
least one opt-in is confirmed and removes it when the last one goes. No pairing may name
`papaia-chat-relay` as audience, so no `aud-papaia-chat-relay` scope exists and no other
client can obtain a token for the relay. Like `papaia-data`, the relay is the one named
exception to the rule that an exchange client is never an audience.

**3. The relay's client.** `papaia-chat-relay` is a confidential client of the core
(owner `papaia`), with client authentication `private_key_jwt` (key file generated by
`papaia-ctl start`, mounted into the relay alone), `standard.token.exchange.enabled`,
`fullScopeAllowed: false`, no sign-in of persons, no `client_credentials`, no
`offline_access`, no default `aud-*` scope. Its optional scopes are exactly the
`aud-<audience>` scopes of the confirmed opt-ins (at most 12, the realm's limit per client),
never the audience of a suite server, a core profile or `papaia-chat-relay` itself.
The realm policy `chat-relay` (conditions: grant type token exchange and the client
attribute `papaia.chat-relay=true`, which the sync sets on this client only) checks the
subject token with `jwt-claim-enforcer`: `azp` must be `librechat`. The existing
one-audience policies (`papaia-one-aud-<x>-<y>`) apply to the relay like to every managed
client, so an exchange for two add-ons at once is refused by the identity provider, not only
by the relay.

**4. The opt-in.** Per add-on, off by default, revocable:

- `papaia-ctl addon chat allow <addon>` is accepted only for an installed, active add-on
  whose catalog entry has `kind: mcp`, `identity` with `person`, an address, a registered
  audience and `trust: addon`. It is refused for a suite module or core profile (they need
  no opt-in), for an unknown name, for an add-on that attaches `librechat` to one of its
  networks (a direct path between the add-on and the chat), and for an add-on whose audience
  is also a client with token exchange (the relay's token could be exchanged onwards).
  Before it asks, the command shows the add-on, its audience, its declared operations with
  their effects and the entry's data class cap (see 6).
- The opt-in is recorded as a pairing of `papaia-chat-relay` with the add-on's audience in
  `security/pairings.yaml`, with the effects of the declared operations (`read` and `check`
  as `r`, `write` and `send` as `w`, `delete` as `d`). The pairing rules apply unchanged: a
  pairing with `w` or `d` is confirmed only by a second host account (`requested_by` and
  `confirmed_by` differ); a read-only opt-in also waits for a second host account while
  `approvals.four_eyes` is on, which it always is in the security profile `kritis`. The
  second host account confirms with `addon chat allow <addon>`; the same account is refused.
  `pairing approve` refuses the client `papaia-chat-relay`: the opt-in has exactly one path.
  The realm sync refuses a pairings file that pairs the relay with an audience that is not
  eligible as above.
- `papaia-ctl addon chat revoke <addon>` removes the pairing in any state and renders the
  relay's list at once: from that moment the relay refuses the add-on. The next realm sync
  removes the scope from the relay's client. Uninstalling the add-on removes the pairing;
  stopping it, or the entry losing its eligibility (for example because the add-on joins the
  suite and becomes `trust: platform`), drops it from the relay's list at the next render.
- The trust level stays `trust: addon` in the catalog. The opt-in lives in the pairings file
  and the relay's list, not in the catalog; the catalog's own chat entries for `trust:
  platform` stay as they are.

**5. Audit.** Every decision and every relayed call is one `papaia.audit/1` row, never with
a token value, tool arguments or results:

- `papaia-ctl/chat-relay` writes `chat_relay.allow` (a request that waits, or an opt-in
  that takes effect), `chat_relay.approve` (the second host account) and
  `chat_relay.revoke`, event `exchange_right_changed`, `sub` the host account, `object_ref`
  `addon`/`<addon>`, `catalog_id` the entry and `data_class` its cap. A refused attempt is a
  row too (`result: denied`, for example `same_person` or `not_eligible`).
- `papaia-chat-relay` is a source of its own with an ingest certificate and writes one row
  per request it receives for an add-on: `chat_relay.tool_call` for `tools/call`,
  `chat_relay.session` for the other methods, event `operation`, role `caller`, `sub` the
  person, `azp` `librechat`, `aud` the add-on's audience, `catalog_id`, `object_ref`
  `tool`/`<addon>/<tool>`, the declared `effect` and the operation's `data_class_max`,
  `result` and `error_code`, and the correlation id. The relay takes the
  `X-Papaia-Correlation-Id` of the request when it is valid, otherwise it sets a new one,
  sends that to the add-on and returns it. A refused request (token, target, method, tool,
  arguments, limit) is a `denied` row; a call whose row cannot be written to the outbox is
  not forwarded.

**6. Data class cap.** The cap of an entry is the highest `data_class_max` of its declared
operations. `addon chat allow` shows it before it asks, the audit rows of the opt-in carry
it, and the chat entry's description ends with it, so the person sees in the chat which data
the server may return.

## Security assessment

- **Trust rule kept.** The shared chat token stays with the suite servers and the relay. An
  add-on outside the suite sees only a token with exactly one audience, its own, with `azp`
  `papaia-chat-relay` and the person's `sub`; it cannot present that token to a suite server
  (each checks `aud`) or to another add-on. The add-on keeps `trust: addon`, and nothing of
  its manifest can raise it.
- **Token scope.** Exactly one audience per exchanged token, enforced twice: the relay asks
  for one `aud-*` scope and checks the answer, and the identity provider's one-audience
  policies refuse two. The exchanged token lives at most as long as the realm's access tokens
  (240 s); the relay refuses one with more than 300 s remaining, one whose `aud` is not
  exactly the target, whose `azp` is not `papaia-chat-relay` or whose `sub` differs from the
  chat token's. There is no refresh token: the relay asks for an access token only, its
  client is set never to issue a refresh token in an exchange, and an answer that carries one
  is treated as an error. The relay keeps no token beyond the call it serves: no cache, no
  file, no log.
- **Least privilege.** One new client, one audience and one mapper, all named in the
  register before use (`papaia-<module>[-<surface>]`: module `chat`, surface `relay`),
  and one network `papaia-chat-relay-net` (`internal: true`, only `librechat` and the relay).
  The relay further joins the network of each allowed add-on's address (its app network or
  the network it offers, ADR 0027), the network on which core services reach the identity
  provider and `papaia-audit-ingest-net`; it publishes no port, runs as non-root on a
  read-only file system and holds no other secret. `librechat` joins no network of an allowed
  add-on: `addon chat allow` refuses an add-on that attaches it.
- **Opt-in.** Off by default; per add-on; a second host account for every write and, with
  `approvals.four_eyes` on, for every opt-in; revocable at once; refused where the add-on
  could reach the chat directly or exchange the token onwards.
- **Server-side checks.** The relay decides from the chat token, its own list and the
  catalog; LibreChat's configuration is never the control. The add-on still checks `aud`,
  the person's rights and its own data rules on every call.
- **Input at the boundary.** Path segment, method, tool name and arguments are checked
  against the list and the declared schema; unknown fields of the JSON-RPC envelope are
  refused; sizes, time and rate are limited.
- **Failure modes.** The path fails closed: a missing or invalid list, a token that does not
  check, an exchange the identity provider refuses or cannot answer, an answer with a
  refresh token, a second audience or a longer lifetime, an add-on that is stopped, does not
  answer in time or answers with more than the limit, and an outbox that cannot take the row
  each end the call with a JSON-RPC error to the chat and a row with the reason
  (`token_invalid`, `not_allowed`, `exchange_refused`, `idp_unavailable`,
  `upstream_unavailable`, `upstream_timeout`, `response_too_large`, `audit_unavailable`).
  Nothing falls back to a direct call or to the chat token.
- **External identity provider.** With `external_oidc` the core does not manage the realm.
  `addon chat allow` then lists the objects to create there (the client, the scope
  `aud-<audience>`, the mapper on the chat's client and the two policies), and the relay
  refuses every call until the exchange answers as above.
- **Remaining risk.** The relay holds the shared chat token in memory for the duration of
  one call; a flaw in the relay is a flaw of the core, not of an add-on. Tool results go to
  the chat's model as content; the cap shows their class, and which models may see which
  class stays the model policy's decision.

## Consequences

- **Positive**: An add-on outside the suite can serve the chat without joining the suite and
  without ever seeing the shared token. The path reuses the register, the exchange scopes,
  the pairings with their second person and the audit outbox. Every opt-in and every call
  can be traced by person, add-on, tool and correlation id.
- **Negative**: One more core service that holds the shared token in memory, and one token
  exchange per relayed request (latency, load on the identity provider). At most 12 add-ons
  can be allowed per installation. An add-on that attaches `librechat` must drop that
  attachment before it can be allowed. Resources, prompts and requests back to the chat are
  not available through the relay.
- **Neutral**: Suite servers are unchanged and keep the direct path. The names
  `papaia-chat-relay` (client and audience) are registered in the platform kit before the
  core uses them. The implementation of the relay and of the opt-in commands follows this
  decision; until then, a tool server outside the suite has no way into the chat.

## Alternatives considered

- **Add the add-on to the suite** (list it in `compat/suite.yaml`). It would become `trust:
  platform` and receive the shared chat token, with the audiences of every suite server.
  Rejected by the owner: an add-on that stays outside the suite's acceptance must not hold
  that token, and the trust level must not change to make the chat work.
- **A sign-in client per add-on in the chat.** Each add-on would get its own client in
  LibreChat with its own sign-in. Rejected: it depends on features of the chat that the core
  does not control, needs one more client, sign-in address and secret per add-on, and puts
  a second sign-in in front of the person.
- **Pass the shared chat token** to the add-on, as for suite servers. Rejected: it leaks the
  audiences of every suite server to a server outside the suite, which could then act as the
  person at each of them.
- **Let LibreChat exchange the token itself** per server. Rejected: LibreChat has no
  exchange per tool server, and the core would again depend on chat features outside its
  control.
- **A relay per add-on**, shipped by the add-on. Rejected: the relay would hold the shared
  token inside the add-on's trust boundary, which is exactly what this decision prevents.

## References

- `tools/lib/chat_servers.py`, `tools/lib/realm_sync.py`, `tools/lib/names_register.json`
- [`docs/architecture.md`](../architecture.md), Seam 2 (pairings, exchange scopes, one
  audience per token) and Seam 3 (the chat's tool servers)
- [`docs/audit.md`](../audit.md) (`papaia.audit/1`, ingest sources)
- ADR 0018 (identity: roles, exchange scopes and service accounts), ADR 0027 (offered
  networks), ADR 0028 (sign-in addresses of add-on clients)
- RFC 8693, OAuth 2.0 Token Exchange
