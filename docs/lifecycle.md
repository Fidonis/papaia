# Account lifecycle and revocation (papaia-lifecycle)

`papaia-lifecycle` makes the deactivation of an account take effect everywhere: when an
account of the `papaia` realm is deactivated or deleted, it ends the person's sessions,
removes every consent the person gave (offline sessions and with them the delegations of
Flow and the assistant) and puts the person on a signed revocation list that every module
reads. Every such change, and every removed role or group, ended session and reset
credential, is a line of the erasure journal `identity` at the backup target, so a
restored snapshot cannot bring it back (see [The erasure journal](#the-erasure-journal-identity)).

It is optional and needs the bundled Keycloak. Switch it on by adding `lifecycle` to
`COMPOSE_PROFILES` in `src/.env` (or the root `.env` of the configuration directory) and
run `papaia-ctl start`. The realm sync then sets up its service account.

## What it does

Every 10 s the service reads the admin events of the realm (`UPDATE`, `DELETE` and
`ACTION` of an account, removed realm and client role mappings and group memberships).
For an account that is now deactivated:

1. the person goes on the revocation list, `since` = time of the event;
2. `POST /users/{id}/logout` ends every session;
3. `GET /users/{id}/consents`, then `DELETE /users/{id}/consents/{client}` for each
   client removes every consent.

Step 3 is needed: logout alone leaves offline sessions alive, and a reactivated account
would get its old delegations back. After the three steps a refresh with an old offline
token fails, also after the account is activated again; the person grants delegations
anew. A deleted account goes on the list only (Keycloak removed its sessions with it).

If a call to Keycloak fails, the entry stays on the list and the event is handled again
on the next cycle. An event that fails on 3 cycles in a row is *parked*: later events
(other deactivations) go ahead, the parked event is tried again on every cycle until it
succeeds, and health reports `parked_revocations` and warns while one is parked. Events
are read from where the last run stopped; on the very first start the last 60 s are read
as well.

Admin events are kept in Keycloak for 7 days (see below). If the service is stopped for
longer, events are lost; the reconciliation independent of events closes that gap.

Removed roles and groups, ended sessions and reset credentials are written to the
journal only; the service does not act on them in Keycloak. Not handled here: the
regular reconciliation independent of events, federated directories, the signal to the
modules' `/internal/lifecycle` and replaying the journal (the core start gate).

An account outside the group `papaia-persons` (see below) cannot be read by the service
(Keycloak answers 403), so it is **not revoked**: for example a person someone removed
from the group by hand. The service writes one audit row (`lifecycle.revoke`, `result:
denied`, `error_code: http_403`), logs a note and counts the account in health
(`skipped_revocations`, accounts of the last 181 days). This gap is part of the residual
risk below: check the count, put the person back into the group (the next realm sync
does this) and deactivate the account again.

## The erasure journal `identity`

Account states must survive a restored snapshot (a backup, a VM or volume copy) just like
deletions in the modules. The service therefore writes one line per change to
`$PAPAIA_BACKUP_DIR/erasure-journal/identity.jsonl`, in the line format of the modules'
erasure journals, and keeps a local copy in its own volume `papaia-lifecycle-key`
(`erasure-journal/identity.jsonl`, not backed up). The journal at the backup target is
the reference: a snapshot of the host brings back an older local copy, not an older
target.

| Admin event | `kind` | `object_ref` | `reason` |
|---|---|---|---|
| account updated and now disabled | `account_disable` | `account` | `account_disabled` |
| account deleted (also: updated, then gone) | `account_delete` | `account` | `account_deleted` |
| realm roles of an account removed | `role_revoke` | `realm-roles` | `role_removed` |
| client roles of an account removed | `role_revoke` | `client-roles:<client id>` | `role_removed` |
| account removed from a group | `role_revoke` | `group:<group id>` | `role_removed` |
| sessions of an account ended by the administration | `session_revoke` | `sessions` | `sessions_ended` |
| password reset by the administration | `credential_reset` | `password` | `credential_changed` |
| credential (for example a second factor) removed | `credential_reset` | `credential:<credential id>` | `credential_changed` |

Each line is `{id, module, seq, kind, object_ref, subject_ref, at, reason}`, without
content. `module` is `identity`; `seq` rises by one per entry, without gaps;
`subject_ref` = HMAC-SHA256 of the account id under the installation key `erasure-hmac`,
so the journal names nobody in clear. The key is made once by `papaia-ctl setup`/`start`
(`render`) at `$PAPAIA_CONFIG_DIR/security/erasure-hmac` (mode 0600, mounted read-only)
and is part of the backup of the configuration directory, never next to the journal; do
not replace it, or old entries can no longer be matched to an account. The admin events
are stored without representations, so a role entry names the scope (realm roles, the
client, the group), not the single role. The service's own logout after a deactivation
is not a second entry. An admin event the service may not read the account of (outside
`papaia-persons`) writes no entry.

The journal is written after the revocation. If the backup target cannot be written (not
mounted, full, damaged file), the revocation still goes ahead: the entry waits in the
local copy and is delivered on the next poll; meanwhile health reports `journal_pending`
and `journal_target` and warns. An entry the target receives under another `seq` than
first handed out (the local copy was older than the target) keeps that first number as
`provisional_seq`. If the local copy itself cannot be written, the event is tried again
and parked like a failing revocation; later revocations go ahead, and health fails while
the local copy is damaged.

`render` also creates the folder `$PAPAIA_BACKUP_DIR/erasure-journal` (mode 0700) before
the start. Compose does not create it (an empty folder in place of an unmounted backup
target would look like an empty journal), so the container does not start while the
folder is missing: mount the backup target and run `papaia-ctl start` again. Of the
backup target the service sees this folder only. Each write is one audit line
(`lifecycle.journal`, object `erasure_journal` `identity:<seq>`, the correlation id of
the event; `error`/`journal_unavailable` when the local copy fails).

The writer also accepts the core sources `core-chat` (`erase`, `erase_subject`) and
`model-gateway` (`erase`, `erase_subject`, `key_revoke`) in their own files; the deletion
of a person in chat and model gateway and the revocation of gateway keys write them.

## The revocation list

Written to the volume `papaia-security-state`, which modules mount read-only:

| File | Content |
|---|---|
| `revocations.json` | `{seq, issued_at, global_since?, entries: [{sub, since, reason}]}`, times in seconds since the epoch, compact JSON with sorted keys |
| `revocations.json.sig` | Ed25519 signature (64 raw bytes) over the exact bytes of `revocations.json` |
| `revocations.pub.pem` | the public key (SubjectPublicKeyInfo, PEM) |

A module refuses a token with `identity_revoked` when its `iat` is before `global_since`,
or before `since` of a listed `sub`. `reason` is `account_disabled` or `account_deleted`.
The list is issued again every 15 s, also without a change, with a new `seq` and
`issued_at`; `revocations_age_seconds` = now − `issued_at` tells a module how fresh it
is. The list is written first, then the signature: a reader that finds a pair that does
not verify keeps its previous list and reads again. Entries older than 181 days are
dropped (no token can be older).

`global_since` invalidates every token issued before it, for everyone. It only moves
forward, so a time more than 300 s in the future is refused:

```sh
docker compose exec papaia-lifecycle python3 -I /opt/papaia-lifecycle/lifecycle.py \
  global-since --key-dir=/var/lib/papaia-lifecycle --state-dir=/var/lib/papaia-security-state
```

(`--at <seconds>` sets a given time; without it, now.) The command only records the
value; the running service publishes it within a second and writes the audit rows
(`lifecycle.global_since`, `lifecycle.revocation_list`) to its own log. The command waits
up to 20 s for the published list and says when it has not appeared yet.

The signing key is made on the first start in the volume `papaia-lifecycle-key`, which
`papaia-ctl backup` leaves out. After a restore the service makes a new key, so an old
key from a backup can never sign lists again. Modules that keep a copy of the public key
must take the new one then.

## Health

The container's health check runs `lifecycle.py health`, which prints for example

```json
{"journal_pending": 0, "journal_target": "ok", "last_poll_age_seconds": 4,
 "parked_revocations": 0, "revocations_age_seconds": 3, "seq": 812,
 "skipped_revocations": 0, "status": "ok"}
```

and fails (`warn` above 60 s, `fail` above 300 s) when the list is old, does not verify,
or Keycloak has not been read for that long; it warns while an event is parked or a
journal entry is not at the backup target yet (`journal_target`: `ok`, `unreachable`,
`corrupt`), and fails while the local copy of the journal is damaged. A
restart does not reset `last_poll_age_seconds`: a poll that keeps failing stays visible.

## The service account `svc-papaia-lifecycle`

While the profile is active, `papaia-ctl realm sync` (also run by every `start`) keeps:

| Object | Setting |
|---|---|
| Client `svc-papaia-lifecycle` | `client_credentials` with `private_key_jwt` (ES256) only; no sign-in flow, no password grant, no token exchange, `fullScopeAllowed: false`. The private key is `$PAPAIA_CONFIG_DIR/security/service-accounts/svc-papaia-lifecycle/private-key.pem` (made by `setup`/`start` before the container starts; mounted read-only) |
| Its service-account user | `realm-management` `view-events` only (reading admin events), also in the client's token scope; no other role, no group, no `manage-users` |
| Group `papaia-persons` | a default group; every account except service accounts is a member |
| Admin permissions | switched on for the realm (`adminPermissionsEnabled`); one permission on resource type Groups, scopes `view-members` and `manage-members`, for `papaia-persons`, granted to the client alone |
| Admin events | stored (`adminEventsEnabled`), without representations, kept 7 days (realm attribute `adminEventsExpiration` = 604800; a retention the operator set is kept, none or 0 is replaced). They name actor, address and resource path; the lasting record is papaia-audit |

That permission is the smallest set with which logout and consent removal work in
Keycloak 26.7.0. **Residual risk:** it is finer than `manage-users` by reach (members of
`papaia-persons` only; no account creation, no role mapping, no group membership changes,
nothing outside the group), not by operation. Whoever holds the private key can also
change the mail address or password of, disable or delete any member of the group and so
take over the account. Measures: the service has no other function, its only network is
`papaia-lifecycle-net` (internal, shared with Keycloak alone), no port, a read-only file
system without capabilities, the key is mounted read-only with mode 0600, and every
write is an audit line. The group includes person accounts holding `papaia-admin`:
leaving them out would leave their delegations unrevoked. This residual risk is accepted
as named here. Two further gaps belong to it: an account outside the group is not revoked
(`skipped_revocations`, above), and the switches `adminPermissionsEnabled` and
`adminEventsEnabled` and the group stay in the realm after the profile is switched off.

Without the profile the realm sync removes the client, its key folder and the
permission; the group and the realm switches stay. The account is not one of the
declared accounts, so `papaia-ctl service-account rotate` does not cover it yet: delete
its key folder and run `papaia-ctl start` to replace the key.

## Audit

Every logout, every consent removal, every journal entry and every change of the list's
content (not the 15 s reissue) is one `papaia.audit/1` line on the service's standard output, with one
correlation id per handled event, the service account as actor and the person's `sub`
as object. So is an account that could not be revoked (`lifecycle.revoke`, `denied`), an
event parked after repeated failures (`lifecycle.revocation_parked`, `error`,
`retries_exhausted`) and a new `global_since` (`lifecycle.global_since`, written by the
service also when the command set it). Tokens, assertions and Keycloak's answers are
never printed.

```sh
docker compose logs papaia-lifecycle | grep '"format": "papaia.audit/1"'
```

## Distributed installations

The service must run on Keycloak's node (it is placed together with `keycloak`).
