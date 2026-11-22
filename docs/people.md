# People lookup

`papaia-people` lets the assistant find a person to add to a group room, and Studio
address the members of a group an app is shared with, without any module getting a right
on the directory. It answers two questions, each for one caller, with the least the
caller needs: "who is the person with exactly this name or mail address and this
assistant role?" (the assistant's gate) and "which active members of this share group
hold this Studio role, if they are 50 or fewer?" (Studio's gateway). It is an optional
core service, profile `people`.

## What it answers

```
GET /v1/people/lookup?q=<full display name or full mail address>&role=<assistant role>
Authorization: Bearer <person token for the audience papaia-people>
X-Papaia-Correlation-Id: <optional, 1 to 64 of A-Z a-z 0-9 ->
```

```json
{"people": [{"sub": "0b9c7b1e-…", "display_name": "Anna Albers"}]}
```

| Rule | Behaviour |
|---|---|
| Exact match only | A hit is an account whose whole display name (first and last name) or whole mail address equals `q`, ignoring case. A prefix (`Anna Alb`), a single word, an initial, a wildcard (`*`, `%`), an empty or partial mail address, or text that is not in Unicode NFC is refused with 400 `invalid_query`. At most 5 hits; never a list of the directory. |
| Role filter | `role` is `assist-member` or `assist-admin` (any other role: 403 `role_not_allowed`). Only enabled accounts that hold the role, directly, through a group or a composite, are returned; service accounts never. |
| Parameters | Exactly `q` and `role`, each once (unknown: 400 `unknown_parameter`, repeated: 400 `duplicate_parameter`, missing: 400 `missing_parameter`). |
| Answer | `sub` and `display_name` only. |
| Caller | A person token (it carries `sid`) of the `papaia` realm, signed with one of the realm's keys (RS256), issuer `OIDC_ISSUER`, audience exactly `papaia-people`, `azp` = `assist-gate`, not expired (30 s clock tolerance). A bad, foreign or expired token: 401 `invalid_token`. Another client: 403 `client_not_paired`. A service token: 403 `person_token_required`. |
| Rate limit | 30 requests per person and 10 minutes, and 300 per calling client and 10 minutes (`--per-client`). Every admitted request counts, an invalid one too. More: 429 `rate_limited` with `Retry-After`. |
| Directory down | 502 `directory_unavailable`. |

## Group members for Studio

```
GET /v1/people/group-members?group=<group id>[&role=<Studio role>]
Authorization: Bearer <person token for the audience papaia-people>
X-Papaia-Correlation-Id: <optional, 1 to 64 of A-Z a-z 0-9 ->
```

```json
{"members": ["0b9c7b1e-…", "5d0f6a2b-…"]}
```

or, for more than 50 members, `{"too_many": true}` without a list. Studio sends one
notice per listed person; for a larger group it only adds the entry in "My tasks".

| Rule | Behaviour |
|---|---|
| Caller | As for the lookup, but `azp` = `papaia-studio-gateway`. The Studio gateway reaches only this route and the assistant's gate only the lookup; any other client: 403 `client_not_paired`. A service token: 403 `person_token_required`. |
| Group | `group` is one whole group id of the identity provider (letters, digits and `-`, at most 64). A wildcard (`*`, `%`), a path, a space or an empty value is refused with 400 `invalid_group`. The group must be offered for sharing: listed in `$PAPAIA_CONFIG_DIR/platform/groups.json` and not technical; otherwise 403 `group_not_offered`. Studio checks before asking that the person shares an app with the group or gives it to review there; the service checks the list. |
| Role filter | `role` is `studio-member` (the default), `studio-author`, `studio-reviewer` or `studio-admin`; any other role: 403 `role_not_allowed`. |
| Members | Enabled accounts that are members of the group or of one of its subgroups (the same resolution as the `groups` claim Studio checks access with) and hold the role, directly, through a group or a composite. Deactivated accounts and service accounts are never members; an account in several subgroups counts once. |
| Bound | At most 50 members in the answer; with 51 or more: `{"too_many": true}`. The service stops reading the group as soon as the 51st member is found, and answers `too_many` as well when the group holds more than 1000 accounts to look at. |
| Answer | `sub` only, sorted; no names, no mail addresses. |
| Parameters | Exactly `group`, optionally `role`, each once (unknown: 400 `unknown_parameter`, repeated: 400 `duplicate_parameter`, missing `group`: 400 `missing_parameter`). |
| Rate limit | The same windows as the lookup: 30 requests per person and 10 minutes and 300 per calling client (`--per-client`); every admitted request counts. More: 429 `rate_limited` with `Retry-After`. |
| Group list unreadable | A missing file or one that is not `papaia.platform-groups/1` offers no group: 503 `group_list_unavailable`. A file replaced by `realm sync` is read again on the next request. |
| Directory down | 502 `directory_unavailable`. |

The member list exists only in the memory of the one request and in the answer to
Studio; it is never written to a log, an audit row or a file. Studio keeps it only in the
memory of the notice run and never hands it to the browser.

Subgroups are taken from `platform/groups.json`: a subgroup created after the last `realm
sync` is not resolved until the next one, so its members get no notice until then (they
still find the entry in "My tasks").

Other paths answer 404, other methods 405. `GET /healthz` answers `{"status": "ok"}` for
the container health check and reveals nothing else.

## Audit

Every request with a verified token writes one `papaia.audit/1` row on stdout:
`writer` `papaia-people`, `role` `server`, the caller's `sub`, `identity_kind`, `azp`,
`aud` `papaia-people`, `catalog_id` `people.lookup`, `operation` `people_lookup`, `effect`
`read`, `object_ref` `{type: role, id: <role>}`, the result (`allowed`, `denied`,
`error`) with its error code, `detail.count` = the number of hits and the token times
(`token_iat`, `token_auth_time`, `token_remaining_s`). A refused rate limit is a
`denied` row with `rate_limited`. The row never holds the search text, a name, a mail
address or a token, and the request line is never logged. A request without a verifiable
token writes no row: there is no identity to name.

A request to the group route writes the same row with `catalog_id`
`people.group_members` (the kind `group`), `object_ref` `{type: group, id: <group id>}`
once the id is well formed, and `detail.count` = the number of members answered. A
`too_many` answer is an `allowed` row with `error_code` `too_many` and no count. The row
never holds a member's `sub`.

## Realm objects

While the profile `people` is active, `papaia-ctl realm sync` keeps:

| Object | Shape |
|---|---|
| Service account `svc-papaia-people` | client_credentials with `private_key_jwt` (ES256) only, key pair in `$PAPAIA_CONFIG_DIR/security/service-accounts/svc-papaia-people/` (made by `render`), no sign-in flow, no token exchange, `fullScopeAllowed: false`. Its user holds `realm-management` `query-users`, `view-users` and `query-groups` and nothing else, also in its token scope: no write right, no other role, no group. A wider right is reported by `realm sync --check` and removed by `realm sync`. |
| Audience `papaia-people` | a bearer-only client (owner `papaia`) and the exchange scope `aud-papaia-people`; persons only (no `client_credentials`, no exchange without `sid`). |
| Pairings | only `assist-gate` → `papaia-people` (the lookup) and `papaia-studio-gateway` → `papaia-people` (the group members), each effect `x`, from `$PAPAIA_CONFIG_DIR/security/pairings.yaml` once confirmed. A pairing of any other client, or with another effect, stops the sync before any change. The service binds each client to its one route. |

`query-users` alone finds nobody and cannot read role mappings, so the account needs
`view-users` (measured against Keycloak 26.7.0). The group members need `query-groups`;
Keycloak makes `view-users` a composite that already holds it, and the realm sync maps it
explicitly so the bound is named. No further `realm-management` role is granted.

Without the profile the service account and its key folder are removed, the audience
client is no longer managed and the pairing waits ("inactive until both sides are
installed").

## Operation

Switch it on by adding `people` to `COMPOSE_PROFILES` in `src/.env`, then `papaia-ctl
render`, `papaia-ctl start` and `papaia-ctl realm sync`. The service publishes no port; it
listens on the stack network as `http://papaia-people:8080` and runs next to Keycloak. It
mounts `$PAPAIA_CONFIG_DIR/platform` read-only for the group list, keeps no state and no
volume, runs as the configuration directory's owner on a read-only
file system without capabilities, and reaches Keycloak at `https://keycloak:8443` with the
local CA. It reads the realm's signing keys from Keycloak and reads them again when a
token names an unknown key (at most every 30 s) and at the latest every 5 minutes.

The service reads its key file again for every sign-in, so a replaced key file takes
effect once `realm sync` has registered the new public key.

Limits of this release: tokens are checked for signature, issuer, audience, client and
lifetime; the signed revocation list of `papaia-lifecycle` is not consulted, so a person
deactivated a moment ago can use a token they already hold until it expires (at most the
access token lifespan of the realm).
