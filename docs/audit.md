# The audit store

`papaia-audit` is the one place that keeps the audit events of the stack. Every module and
every server writes its events in the format `papaia.audit/1` into a local outbox and
delivers them to `papaia-audit`; nothing else stores or serves audit events. The store is
append-only: one hash chain per source, signed chain heads, and a verification job that
names the first event that no longer fits.

The service is always on (profile `audit`, like the single exit). `papaia-ctl setup` keeps
the profile in `COMPOSE_PROFILES`; `papaia-ctl start` creates the certificates, passwords and
the signing key before the containers start and never replaces existing ones.

Reading is described under [Reading](#reading), retention and the deletion lock under
[Retention](#retention), the export under [SIEM](#siem).

## Containers, networks, ports

| Container | Networks | Purpose |
|---|---|---|
| `papaia-audit` | `papaia-audit-net`, `papaia-audit-ingest-net`, `papaia-audit-idp-net` (Keycloak only, for the permission report; and its egress network while a SIEM target is set) | ingest and read API on `:8443` (mutual TLS), `verify`, `heads`, retention, SIEM export |
| `papaia-audit-schema` | `papaia-audit-net` | one shot before `papaia-audit`: creates the store and sets the role passwords |
| `papaia-audit-db` | `papaia-audit-net` | PostgreSQL 17, volume `papaia-audit-pgdata` |

`papaia-audit` and `papaia-audit-schema` run the core's own image
`ghcr.io/fidonis/papaia-audit`, pinned by digest and signed like every other image (see
[`compatibility.md`](compatibility.md#own-images-of-the-core)); nothing of the checkout is
mounted into them. The image carries the service, the schema and the Python packages, which
are wheels pinned by hash (`src/infra/audit/requirements.txt`).

Both networks are `internal: true`. No port is published. The database is reachable from
`papaia-audit` and `papaia-audit-schema` only; no add-on may attach `papaia-audit-db` or
`papaia-audit-schema` (`papaia-ctl addon check` refuses such a manifest). Sources reach `papaia-audit:8443` on `papaia-audit-ingest-net`.
Like the manager and the single exit, the service runs on the controller of a distributed
installation, because it mounts its certificates and secrets from the configuration
directory.

## Ingest

`POST https://papaia-audit:8443/v1/ingest`, `Content-Type: application/x-ndjson`, 1 to 500
lines, one event per line, ascending `source_seq`. The platform kit's audit writer sends
exactly this; its contract (outbox, retries, acknowledgements) applies unchanged.

**Who may deliver.** The TLS handshake requires a client certificate issued by the ingest
CA of this installation. The source of every event is the common name of that certificate,
and the certificate counts only while its SHA-256 fingerprint is listed for that source in
`service/sources.json`. Anything else is refused:

| Situation | Answer |
|---|---|
| no client certificate, or one from another CA | TLS handshake fails |
| certificate of the CA, but not listed (replaced or never issued through `papaia-ctl`) | `403`, `audit.unknown_source` |
| path other than `/v1/ingest`, wrong content type, no or too large length | `4xx`, `audit.invalid_request` |

**What is stored.** Lines are handled in order. A line is stored only when it

- is a JSON object of at most 16 KiB with no duplicate keys, no fractions and no `NaN`,
- passes the `papaia.audit/1` submission schema (unknown fields, token-shaped values,
  impossible dates and the fields `source`, `seq`, `prev_hash` and `hash` are refused),
- names its own source in `writer` (`<source>` or `<source>/<component>`), and
- carries the next `source_seq` of the source (the highest stored plus 1, or 1).

A `source_seq` that is already stored is a repeated delivery: it is acknowledged with the
`seq` it already has and not stored again. At the first line that is not stored the request
ends; the lines before it are acknowledged (`200`, `{"acknowledged": [{"source_seq": …,
"seq": …}]}`). When already the first line is refused, the answer is `422` with
`{"error_code": "audit.invalid_submission" | "audit.unsupported_format" |
"audit.source_seq_gap"}`; with the database unreachable it is `503`. A gap in `source_seq`
is never closed by `papaia-audit`: it means that rows were removed from a source's outbox.

The service logs reason codes, sources and line counts only, never an event.

The schema file `src/infra/audit/papaia_audit/audit.v1.schema.json` is a copy of the
`papaia.audit/1` schema of the platform kit, schema version 1.4.0 (kit 0.1.0); the test suite
runs the kit's submission vectors against the ingest. Revision 1.1.0 adds the optional token
time fields `token_iat`, `token_auth_time` and `token_remaining_s` (integers from 0, or
`null`); a value other than `null` is accepted only in the server's row of an operation
(`role` `server`, `event` `operation`). Revision 1.2.0 adds the events of the erasure journal
and their `detail` fields. Revision 1.3.0 adds the event `delegation_lifetime_changed` and its
`detail` fields `idle_days_old`, `idle_days_new`, `max_days_old`, `max_days_new` (whole days
from 1 to 365, all four or none, only in that event, required when the change was allowed);
the core writes it for every change of the delegation lifetime
([configuration.md](configuration.md#delegation-lifetime)), before the settings file; a
change whose file could not be written is followed by a row of the same correlation id with
`result: error` and `error_code: io`. Revision 1.4.0 adds the event `four_eyes_changed` with
`detail.four_eyes_old` and `detail.four_eyes_new` (`on`/`off`; a stored change carries both
and they differ) and the self-approval flag `detail.selbstfreigabe` (only `true`, only in an
allowed row); the core writes it for every change of `approvals.four_eyes` (README,
`settings`). Rows of earlier revisions stay valid.

## Hash chain and database

Each source has its own chain. `papaia-audit` assigns `seq` (gapless from 1) and computes

    hash = SHA-256(prev_hash || JCS(body))

where `JCS` is the canonical JSON of RFC 8785 and `body` is the submitted event. The first
event of a source has 32 zero bytes as `prev_hash`. One transaction at a time extends the
chain of a source (an advisory lock per source).

Table `audit.event`: `source`, `seq`, `source_seq`, `time`, `received_at`, `prev_hash`,
`hash`, `sub`, `event`, `correlation_id`, `catalog_id`, `result`, `body`; key
`(source, seq)`, unique `(source, source_seq)`, indexes on `correlation_id`,
`(event, time)` and `(catalog_id, time)`. The columns besides the chain fields repeat values
of `body` for searching; verification compares them with the body.

Roles in `papaia-audit-db`:

| Role | May |
|---|---|
| `audit_ingest` | execute `audit.append(source, event)` (security definer) — nothing else, no `SELECT`, no `INSERT` |
| `audit_read` | `SELECT` on `audit.event` and on the tables of retention and export; on `audit.person_request` without the column `archive_key` |
| `audit_retention` | execute `audit.prune`, and write the retention run's own events (`audit.next_seq`, `audit.append_own`, `audit.setting_put`) — nothing else |
| `audit_hold` | the two-person deletion lock of the read API: `audit.legal_hold_request_add`, `audit.legal_hold_request_reject`, `audit.legal_hold_confirm` (which appends the lock event itself), and the request events only (`audit.append_hold`: `approval_changed`, writer `papaia-audit/hold`); the requests for information and erasure (`audit.person_request_add`, `_decide`, `_advance`, `_take_key`, each appending its own event, writer `papaia-audit/person`) — nothing else |
| `audit_owner` | owns the database; its password is a secret of the database container and of `papaia-audit-schema` only |

Triggers refuse every `UPDATE` and `TRUNCATE` on `audit.event`, also for the owner, and
every `DELETE` outside `audit.prune` (see [Retention](#retention)). The owner can switch the
triggers off; such an intervention is not prevented but found by verification.

`audit_ingest` additionally executes the functions that move the SIEM read positions
(`audit.export_targets_set`, `audit.export_advance`) and records report confirmations
(`audit.access_confirmation_add`). `audit.legal_hold_set` and `audit.legal_hold_lift` keep
no grant: only `audit.legal_hold_confirm` (role `audit_hold`) calls them, after it checked
the second person (see [Deletion lock](#deletion-lock)).

## Verification and signed heads

```sh
papaia-ctl audit verify [--source=NAME] [--against=FILE] [--json]
papaia-ctl audit heads > heads-$(date +%F).jsonl
```

`verify` walks every chain (or one) and checks for each event: `seq` follows without a gap,
`prev_hash` is the hash of the event before, `hash` matches the canonical body, and the
search columns match the body. Output per source, exit status 1 if any chain is broken:

    papaia-flow: valid (1832 events, head seq 1832)
    papaia-data: broken at seq 17 (event changed)

A chain that someone with the owner's rights has rewritten consistently, or cut at its end,
still passes alone. `heads` prints one line that signs `(source, seq, hash)` of every
source's last event with the installation's Ed25519 key (`secrets/heads-signing-key`).
Keep these lines outside the host; `verify --against` checks the chains against them and
reports a chain as broken when it no longer contains a signed head. A heads line that this
installation did not sign is rejected. Without a copy outside the host, someone with root
on the host can rewrite chain and heads together.

Both commands run inside the `papaia-audit` container with the `audit_read` role.

The service does both on its own every full hour: it verifies every chain (one log line per
source, `valid` or `broken at seq n`) and appends a signed heads line to
`$PAPAIA_BACKUP_DIR/audit-heads/YYYY-MM-DD.jsonl` at the backup target, and sends it to the
SIEM target (`MSGID` `chain_head`) when one is set. The heads line is written and the
chains verified before it is sent; an unreachable SIEM target or a failure of one duty
(export, heads, verification, retention) is logged and stops none of the others. Keep the
backup target off the host, or use a SIEM: only then can a rewrite by someone with root on
the host be shown.

`papaia-ctl start` creates `audit-heads/` once per backup target and never creates the
target itself: the start stops while `PAPAIA_BACKUP_DIR` does not exist, and once the
folder was made, a missing folder means the target is not mounted.

After a retention run, a chain starts at its anchor (the last removed event): `verify`
checks the first remaining event against the anchor's hash, and the anchor against the
`retention_run` event that recorded it. An anchor that no such event names (moved by hand
to hide removed events) breaks the chain at the event after it. Heads signed before the
anchor are skipped; a head at the anchor must match it.

## Reading

Nothing but `papaia-audit` serves audit events: no module has a route of its own for them.
The read API runs on the same listener as the ingest, `https://papaia-audit:8443`, and
answers only these clients, recognised by their client certificate:

| Client | Routes |
|---|---|
| `papaia-manager` (page "Audit-Log"), `papaia-ctl` | `/v1/events`, `/v1/exports`, `/v1/person-queries…`, `/v1/access-reports…`, `/v1/legal-holds…` |
| `papaia-manager` | `/v1/person-requests`, `/v1/person-requests/<id>/confirm\|reject` (requests for information and erasure, see [person-requests.md](person-requests.md#requests-and-confirmation)) |
| `papaia-me` (page "Aktivität") | `/v1/me/reads` |

Every request carries the bearer token of a person (`Authorization: Bearer …`), obtained by
token exchange for the audience `papaia-audit`: signed RS256 by the realm, issuer and
audience exact (one audience), not expired, with a session (`sid`; a service account's
token has none). The routes of the audit log further need the realm role
`papaia-auditor`; without it every route answers `403` (`forbidden_or_not_found`). The
routes of the permission report and the deletion lock check their own roles (below). Any
other client or path answers `404`. The realm sync grants the two exchange rights for this
audience itself, never through `pairings.yaml`: `papaia-manager` (effect `r`) while the
`audit` profile is on, and `papaia-me` (effect `x`) while `me` is on as well. Errors use the platform's error envelope
(`application/problem+json`: `class`, `code`, `message`, `hint`, `correlation_id`).

**Signing keys.** The service checks tokens against `service/token-keys.json` (format
`papaia.audit-token-keys/1`: the realm's issuer and its RS256 signing keys) and re-reads it
when it changes. Write it after setup and after every rotation of the realm keys:

```sh
papaia-ctl audit token-keys
```

Without the file no token is accepted (`503`).

**Pseudonyms.** Rows show `P-` and eight characters instead of `sub`:
`base32(HMAC-SHA-256(key, sub))`, with the key `secrets/pseudonym-key` that only
`papaia-audit` holds. A pseudonym stays the same for a person; a new key would give every
person a new one, so `papaia-ctl` never replaces it. `client_ip` is left out as well.
An `object_ref` that names a person is shown the same way: its `id` becomes a pseudonym
when its type is `user`, `person`, `member`, `account`, `subject` or `principal`, or when
the id equals the row's `sub`. A ticket (below) reveals only its own person; every other
person in the rows it opens stays a pseudonym.

### Search and export

    GET /v1/events?source=&event=&catalog_id=&result=&correlation_id=&from=&to=&page_token=&limit=

`from`/`to` as `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS[.mmm]Z` (`from` included, `to` not),
`limit` 1 to 500 (default 100), sorted by time, source, seq; `next_page_token` continues the
list. Each row is in the stored form of `papaia.audit/1` (with `source`, `seq`, `prev_hash`
and `hash`); `hash` covers the stored body, which holds the real `sub`. Unknown or repeated
parameters answer `400`. Grouping or counting by person is not offered: `group_by`,
`count`, `count_by`, `per`, `aggregate` and `distinct` answer `403` (`AUDIT-READ-GROUP`).

`POST /v1/exports` with a JSON object of the same filters (without `page_token` and `limit`)
answers JSON lines of the same rows, at most 100 000; event `audit_exported` with the
number of rows.

### Person filter: reason and a second person

A filter by person (`sub`, `pseud` or `ticket`) needs a ticket. It is the same for every
installation, whatever the four-eyes setting of the platform says: nobody confirms their
own request.

1. Auditor A: `POST /v1/person-queries` with exactly `person` (a pseudonym from the log or
   the `sub` of a person), `from`, `to` (at most 93 days) and `reason` (20 to 1000
   characters). Event `audit_person_query_requested`. An unknown pseudonym is `404`; a
   `sub` is taken as given, so the answer does not tell whether that person has events.
   Until the request is confirmed, A's views of it (the answer, the list, a rejection) carry
   no `person`: nothing links the named `sub` to its pseudonym before the second person
   has agreed.
2. Auditor B (another person with `papaia-auditor`) sees the open requests with reason in
   `GET /v1/person-queries` and decides with `POST /v1/person-queries/<id>/confirm` or
   `…/reject`. Confirming needs a sign-in of at most 5 minutes ago (`auth_time`), else `401`
   (`AUDIT-AUTH-FRESH`). Events `audit_person_query_confirmed` or `…_rejected`.
   When A confirms their own request, it is refused (`403`, `AUDIT-PERSON-SELF`, text
   "Sie können Ihren eigenen Antrag nicht bestätigen. …") and the refusal is the event
   `audit_person_query_rejected` with result `denied`; the request stays open.
3. For 60 minutes after the confirmation, A (and only A) reads that person's events of that
   period by name: `GET /v1/events?ticket=<id>` (optionally with `sub` or `pseud` of the same
   person and a narrower period) or the export with `"ticket"`. Then `403`
   (`AUDIT-PERSON-EXPIRED`). Open requests expire after 24 hours.
4. Every read and export with a ticket is the event `audit_read` (or `audit_exported`) with
   the number of rows; it is written before the answer, and without it there is no answer
   (`503`).

A request and a decision are stored in the same database transaction as their own event:
when the event cannot be written, the answer is `503` and nothing changed (no request, the
request still open).

The events of `papaia-audit` itself (source `papaia-audit`, writer `papaia-audit/read`) name
the acting auditor in `sub` and the request in `object_ref` (`person_query`, id). The
request with both persons, the period and the reason is kept in `audit.person_query` in the
same database: the reason is free text, which an event never carries. Rows are added and
decided only through database functions; a check of the table refuses a confirmation by
the requester as well.

### Permission report

papaia-audit builds the permission report ([permission-report.md](permission-report.md),
[ADR 0025](adr/0025-build-the-permission-report-in-papaia-audit.md)) for
`papaia-ctl report permissions` and the manager's audit page:

    POST /v1/access-reports/build   {"by": "person"|"system", "format": "json"|"csv"}

needs a person's token (with `sid`; a service account's token is refused) and the role
`papaia-auditor`; `papaia-admin` alone is not enough. Every call with a valid token is the
event `inventory_exported` (writer `papaia-audit/access`, `operation`
`access_report.person` or `access_report.system`, `object_ref` `access_report` with the
checksum, `detail.rows`), recorded before the answer; also a refused one (`result`
`denied`, `AUDIT-REPORT-403`) and a failed one (`result` `error`). Without the event there
is no report (`503`). The answer is the report itself (`application/json` or
`text/csv`), with the latest confirmation of every row (`last_confirmed_at`,
`confirmation_due`). `POST /v1/access-reports` (the release of a report built on the host)
is removed.

papaia-audit reads the `papaia` realm as the core account `svc-papaia-audit-report`
(client credentials with an ES256 client assertion; key in
`security/service-accounts/svc-papaia-audit-report/`, mounted read-only into papaia-audit
alone). The account holds `realm-management` `view-users` and nothing else; the realm sync
removes any wider right. papaia-audit sends GET requests only, to the report's paths below
`/admin/realms/papaia/users`, over `papaia-audit-idp-net` (internal, shared with Keycloak
alone, row K-21) and checks Keycloak's certificate against `keycloak-ca.crt` in the
service folder. What the account cannot read (clients, pairings, service-account owners,
session limits, the emergency account's id, the recertification period) the realm sync
writes into `infra/audit/service/access-report-inputs.json`, without secrets. Without that
file the build answers `503` `AUDIT-REPORT-INPUTS` ("run `papaia-ctl realm sync`"); when
Keycloak cannot be read, `503` `AUDIT-REPORT-SOURCE`.

    POST /v1/access-reports/confirmations   {"key": "person:<sub>"|"system:<audience>", "digest": "sha256:…"}

is the recertification of one row by the administration (role `papaia-admin`, else
`AUDIT-REPORT-ADMIN`), with the digest of the row it saw. Nobody confirms their own row
(`AUDIT-REPORT-SELF`, a `denied` event). Each confirmation is stored in
`audit.access_confirmation` (rows are only added) together with its event
`approval_changed` (`operation` `access_report.confirmed`, `object_ref` `person` or
`catalog_entry`); both or neither.

From the host, `papaia-ctl` reaches the build and the confirmation through `docker exec` into the
container (`python -m papaia_audit access`, the request with the token on stdin), as the
client `papaia-ctl`; no other route is reachable that way.

### What the affected person sees

`GET /v1/me/reads` (through `papaia-me`, the person's own token, no role) lists each read
or export with a ticket about that person: time, the role `papaia-auditor` (never the name
of the auditor) and the period read. "Mein Bereich → Aktivität" shows it.

## Retention

Events are kept for `PAPAIA_AUDIT_RETENTION_MONTHS` months (default 12, 6 to 36), counted
from their `time`. Every day at 03:30 UTC `papaia-audit` runs retention for every source,
with the role `audit_retention`; `papaia-ctl audit retention` runs it at once. A run
removes, per source, the longest run of events from the start of the chain that are all
older than the limit, and stops

- before the oldest event of a person under a deletion lock, and
- after the last event a SIEM target has taken (see [SIEM](#siem) for a target that is
  no longer configured).

`audit.prune` in the database checks all three limits again and refuses otherwise, so the
role can never remove a younger, locked or undelivered event. The last removed event is
kept as the source's anchor (`audit.anchor`); a source whose events were all removed
continues its chain from there, and a repeated delivery of a removed event is acknowledged
with its old `seq`.

Each run writes one `retention_run` event per source that has an anchor or was held back
into the chain of `papaia-audit` (writer `papaia-audit/retention`, `effect` `delete`,
`detail.count` the number removed). `object_ref` is `audit_anchor` with
`<source>:<seq>:<hash>`; `operation` says what limited the run: `retention.prune`,
`retention.held_back.legal_hold`, `retention.held_back.siem_undelivered`, or
`retention.held_back.store_refused` when `audit.prune` refused the removal (for example a
lock set during the run); such a source keeps all its events until the next run, and the
run goes on with the other sources.

A changed retention or SIEM setting is recorded with one `config_changed` event per setting
(writer `papaia-audit/config`, `object_ref` `setting` with the name, such as
`audit.retention_months`), before the next run.

### Deletion lock

A deletion lock (`audit.legal_hold`) keeps every event of one person (`sub`). It is set and
lifted by two different persons with the role `papaia-legal-hold` and a reason of 20 to
1000 characters, whatever the platform's four-eyes setting says. Lock rows are never
deleted, a lift is recorded in the row. Retention honours locks. No host command sets a
lock.

1. Person A: `POST /v1/legal-holds` with exactly `action` (`set` or `lift`), `person` (a
   pseudonym from the log or a `sub`) and `reason`, after a sign-in of at most 5 minutes
   ago (`AUDIT-AUTH-FRESH`). The body names no acting person: both come from the verified
   tokens. A second lock for the same person, or a lift without a lock, is `409`
   (`AUDIT-HOLD-409`). The request is stored in `audit.legal_hold_request` with the event
   `approval_changed` (writer `papaia-audit/hold`, `operation` `legal_hold.set.requested`
   or `legal_hold.lift.requested`, `object_ref` `legal_hold_request`).
2. Person B (another person with `papaia-legal-hold`) sees the open requests with reason in
   `GET /v1/legal-holds` (persons as pseudonyms, with the active locks) and decides with
   `POST /v1/legal-holds/<id>/confirm` (fresh sign-in) or `…/reject`. A confirmation by A is
   refused (`403`, `AUDIT-HOLD-SELF`, a `denied` event); the database refuses it as well.
   Open requests expire after 24 hours; the database refuses an older one as well, by its
   own clock.
3. The confirmation runs `audit.legal_hold_confirm` with the role `audit_hold`: it sets or
   lifts the lock (`set_by`/`lifted_by` = A, `set_confirmed_by`/`lift_confirmed_by` = B)
   and appends the event `legal_hold_set` or `legal_hold_lifted` itself (`sub` B,
   `object_ref` `person` with the locked `sub`), after checking that the event names B
   and that person. Without the event nothing changes (`503`); the role `audit_hold` cannot
   append a lock event without a change (`audit.append_hold` takes `approval_changed`
   only). This holds for `audit_hold` only: `audit_ingest` keeps `EXECUTE` on
   `audit.append` for the sources it serves, and `audit.append` does not yet refuse a
   `legal_hold_set` or `legal_hold_lifted` body with source `papaia-audit` (follow-up
   CORE-041-F5).

Without the role every route answers `403` (`AUDIT-HOLD-403`). `papaia-ctl realm sync`
creates the realm role `papaia-legal-hold`, never part of `papaia-admin`. An administrator
assigns it in Keycloak. A person's token carries it only through a sign-in client that
lists it in `visible_for_roles`. That is the administration's part (papaia-manager,
MGR-007).

### Requests for information and erasure

`audit.person_request` holds the requests of `papaia-ctl person export|erase` for a person
without an account: filed by the host (`python -m papaia_audit person`, reached only through
`docker exec`, no token), confirmed or rejected by the second person it names through
`papaia-manager` with a sign-in of at most 5 minutes ago, run by the host. The requesting
person cannot confirm (`AUDIT-PERSON-REQ-SELF`), and the database refuses it as well. For an
export, the confirmation returns a one-time passphrase; the store keeps only its scrypt key
until the run takes it. Events: `person_request_created`, `person_request_confirmed`,
`person_request_rejected` and one `operation` row (catalog entry `core.person`) per step of
the run, all with `object_ref` `{type: person_request, id}`. The flow is described in
[person-requests.md](person-requests.md#requests-and-confirmation).

## SIEM

`papaia-audit` is the only component that sends audit events out of the stack. Set the
target in the root `.env`:

| Variable | Meaning |
|---|---|
| `PAPAIA_AUDIT_SIEM_TARGET` | `syslog-tls://host[:6514]` (syslog RFC 5424 over TLS RFC 5425, octet counting) or `https://host[:port]/path` (`POST` of up to 500 JSON lines; 2xx means taken). Empty: no export |
| `PAPAIA_AUDIT_SIEM_PEN` | private enterprise number in the structured data, default `32473` (the example number of RFC 5612) |
| `PAPAIA_AUDIT_SIEM_IDENTITY` | `pseudonym` (default), `sub` or `upstream_oid` (only with a `syslog-tls://` target) |
| `PAPAIA_AUDIT_SIEM_BASIS` | with `sub` or `upstream_oid`: the agreement the export rests on (required) |
| `PAPAIA_OPERATIONS_MAIL` | one address for the warning mails (needs an active mail relay, profile `smtp`); empty: no mail |

A syslog message carries `APP-NAME` `papaia`, `MSGID` the event name and
`[papaia@<PEN> source="…" seq="…"]`; the message is the event in its stored form (with
`source`, `seq`, `prev_hash`, `hash`). With `pseudonym`, `sub` and person ids in
`object_ref` leave as `P-` and 8 characters of base32(HMAC-SHA-256(key, sub)), with the key
`secrets/pseudonym-key` that never leaves `papaia-audit`. With `upstream_oid` the
pseudonym stays and the structured data of the syslog header carries the upstream
provider's tenant and object id from the identity map as two more parameters,
`[papaia@<PEN> source="…" seq="…" tid="…" oid="…"]` (left out for a person the map does
not know), so the SOC can match events with the provider's sign-in logs. The message
itself stays the stored form of `papaia.audit/1`, which allows no further field; a JSON
lines target has no such header, so `upstream_oid` needs a `syslog-tls://` target
(`setup` and the service refuse it otherwise). With `sub`, `sub` leaves in clear
text. `client_ip` leaves with the sign-in events `login_failed` and `breakglass_login`
(and, with `sub`, with every event); otherwise it is left out. `hash` stays that of the
stored event, so it covers the stored identifiers, not the ones sent. A change of
identity or basis is a `config_changed` event.

The queue is the store: each target keeps a read position per source
(`audit.export_cursor`) that moves only after the target took a batch. After an outage or a
restart the export resumes from there, so an event can arrive twice but is never skipped;
receivers recognise a repeat by `source` and `seq`. Retention keeps events a target has
not taken.

A target that is removed from or replaced in the configuration is no longer sent to, but
it keeps holding back every event it has not taken: removing it is not a decision to
discard them. Only `papaia-ctl audit siem skip` releases them, with a reason recorded as an
event. Until then, retention records such a source as `siem_undelivered`.

### Backlog, thresholds and warning mail

There is no buffer of its own and no size limit: undelivered events stay in
`papaia-audit-db`, and retention holds them back. Every minute `papaia-audit` compares
each target's read positions with the chains (one range of the primary key per target and
source, so the cost follows the backlog, not the size of the store) and reads the fill
level of the volume of `papaia-audit-db` (mounted read-only into the service, only for
`statvfs`; the service cannot read a file in it):

| Finding | Result |
|---|---|
| oldest undelivered event older than 60 s, or deliveries failing for more than 60 s | `warn` |
| either for more than 10 minutes | `fail` and one warning mail |
| a target no longer configured that holds events back | `warn`, until `audit siem skip` |
| volume of `papaia-audit-db` 80 % full or more | `warn` |
| volume 95 % full or more | `fail` and one warning mail |
| a chain that does not verify (at the last hourly verification) | `fail` |
| no hourly verification yet, or the last one older than 2 h | `warn` |
| `PAPAIA_OPERATIONS_MAIL` set without an active mail relay | `warn` |

Each mail goes once per outage to `PAPAIA_OPERATIONS_MAIL` through the mail relay
(`smtp-relay`, which then joins the network `<project>-papaia-audit-egress`; it never
joins `papaia-audit-net`), so it needs a SIEM target, whose network the relay joins. The
mail about a target carries the Manager's hint: "Audit-Weiterleitung gestört: Das Ziel
{ziel} nimmt seit {dauer} keine Ereignisse an. …"; the one about the volume: "Audit-Speicher
fast voll: Das Volume papaia-audit-db ist zu {prozent} % belegt. …". Sending is an
`operation` event of `papaia-audit/siem` (`siem.alert_mail` with `object_ref`
`siem_target`, or `store.disk_alert_mail` with `object_ref` `volume` `papaia-audit-db`;
effect `send`; result `error` with `mail_not_sent` when the relay refuses it, which is then
tried again a minute later). A sent mail is marked in `audit.alert_state` before its event
is stored, so neither a restart of the service nor a store that refuses the event brings
a second mail for the same outage; the mark is cleared once the target or the volume is
fine again. `doctor siem` reports the same findings:

    papaia-ctl doctor                  # check `siem`
    papaia-ctl audit siem status       # the service's report as JSON

The report also carries the measurements `papaia_audit_export_lag_seconds{target}`,
`papaia_audit_export_backlog{target}`, `papaia_audit_oldest_event_age_days`,
`papaia_audit_verify_ok{source}` and `papaia_audit_verify_age_seconds`; none of them names
a person. The verification in it is that of the last full hour (kept in
`audit.verify_state`); `papaia-ctl audit verify` walks every chain on demand.

Gaps in `seq` per source are part of that verification: papaia-audit assigns `seq`
without a gap and refuses a delivery whose `source_seq` skips one (the source sends it
again), so a gap in the store means an event is missing. The chain then does not verify,
which `doctor siem` reports as `fail`, not as `warn`: it is tamper evidence, not a delay.

### Releasing undelivered events: `audit siem skip`

    papaia-ctl audit siem skip --source=papaia-flow --until=1200 \
        --reason="Ziel neu aufgebaut, Ereignisse bis 1200 liegen im Archiv 2026-11"

moves the read positions of the source up to that `seq` for every target that has not
taken them, active or not (`--target=<name as doctor siem shows it>` limits it to one).
The reason (20 to 1000 characters) is required; without it the command and the store
refuse. Each moved position is kept in `audit.export_skip` with the reason and the number
of released events, and gives one `config_changed` event (`operation` `siem.skip`,
`object_ref` `siem_position` `<source>@<target>`, `detail.count`), in the same
transaction. The event does not carry the reason. Released events stay in the store
until retention removes them; they are only no longer sent.

### Identity map: `audit idmap`

The map holds, per person, the user name and the upstream provider's `tid` and `oid`. It
is filled through `POST /v1/identities`, which accepts only the client certificate of
`papaia-lifecycle` (at most 500 entries per call, each field checked, unknown fields
refused); an upstream id that moves to another person is taken from the first. Each call
is one `operation` event (`identity_map.put`, effect `write`, `detail.count`) in the same
transaction, without the entries. Until a
person is in the map, `audit idmap` answers only `sub` and the export sends no `tid` and
`oid` for that person. The map is read in two places only: by the export with `upstream_oid`, and for
one person at a time with a confirmed person filter:

    PAPAIA_AUDIT_TOKEN=<token of an auditor> papaia-ctl audit idmap --ticket=<id> --pseud=P-7Q2KXXXX
    PAPAIA_AUDIT_TOKEN=<token of an auditor> papaia-ctl audit idmap --ticket=<id> --tid=<tid> --oid=<oid>

The first answers `sub`, user name, `tid` and `oid` of the person behind the pseudonym,
the second the pseudonym of the person with that upstream id. Both answer only for the
person of the ticket, only to its requester and only within its 60 minutes (the same
route `POST /v1/idmap` serves the Manager). Each answer is a `pseudonym_resolved` event
with the direction in `operation` (`idmap.pseudonym_to_identity`,
`idmap.upstream_to_pseudonym`), and the affected person sees it under "Aktivität". All
pseudonyms at once are not offered. The token is read from the environment, never from
the command line.

A syslog connection is reused only while it is alive. Before every batch `papaia-audit`
checks whether the receiver or `papaia-egress` closed it and opens a new one if so; a
connection idle for 240 s is opened afresh as well (`papaia-egress` closes idle tunnels
after 300 s). RFC 5425 has no acknowledgement, though: a batch written into a connection
that breaks while the batch is underway counts as taken, and is lost if the receiver had
not read it. Where that matters, use an `https://` target, whose 2xx answer confirms each
batch.

The target is reached through `papaia-egress` only: while a target is set, `papaia-ctl`
puts `papaia-audit` on its own internal network `<project>-papaia-audit-egress` and allows
exactly that host and port at the exit (source `papaia-audit`). A target inside the stack is
refused; an internal address must be opened for the source `papaia-audit` like for an
add-on ([egress.md](egress.md)). A private CA of the target goes to
`service/siem-ca.crt`.

## Backup and restore

`papaia-audit-pgdata` is a volume of the core and part of every backup (the database is
paused while its volume is archived); `audit-heads/` lives at the backup target itself. After
a restore the chains are at the state of the restore point: `verify --against` with heads
signed later names the events that are missing, and sources deliver again what they still
hold. SIEM read positions return to the restore point too, so a target may receive events
again.

## Certificates of the sources

```sh
papaia-ctl audit cert <source>
```

issues a client certificate (P-256, 825 days, `clientAuth`) for one source and lists its
fingerprint in `sources.json`; the previous certificate of that source stops working at the
next request. Sources: `papaia-studio`, `papaia-data`, `papaia-flow`, `papaia-assist`,
`papaia-me`, `papaia-connections`, `papaia-manager`, `papaia-lifecycle`, `papaia-egress`,
`papaia-audit`, `mcp-paperless`, `mcp-qdrant`, `mcp-mssql`, `papaia-ctl`. The files land in
`$PAPAIA_CONFIG_DIR/infra/audit/clients/<source>/` (`client.crt`, `client.key` with mode
0600, `ca.crt` to check the server).

`start` (on one host and in a distributed installation) issues the certificate of each
source of an enabled core profile itself, after the audit store's own material and before
the first container: `papaia-me` for the profile `me`, `papaia-connections` for
`connections`. It issues one only when the folder holds no usable certificate: a file
missing, `ca.crt` not the current ingest CA, the certificate not signed by it, expired, not
for `clientAuth` with the source as common name, its key not matching it, its fingerprint
not listed for the source in `sources.json`, or one of the three names not a single regular
file (a symbolic link, a hard link or a special file is never read and is replaced,
reason `not_regular`). A usable certificate is never replaced, so
`audit cert` stays the way to rotate one; sources of profiles that are off and add-on
sources are never issued by `start`. Each issue prints one line and writes one
`papaia.audit/1` row (writer `papaia-ctl/audit-cert`, operation
`audit_cert.issue_<reason>`, object the source and the new fingerprint, never key material)
to the outbox of `papaia-ctl`; a start with nothing to issue prints and writes nothing. When
one cannot be issued, `start` stops with exit 2 before anything starts and names the source
and the cause. A service that stopped for want of its certificate is restarted by Docker
(`restart: unless-stopped`) and reads the mounted folder anew; `papaia-audit` reads the
changed `sources.json` without a restart. Both profiles run on the controller of a
distributed installation only, so the folder `start` fills there is the folder the services
mount.

Which profiles count: those of `start --profiles`; without it, on one host, an exported
`COMPOSE_PROFILES`, which Compose also takes over the env file; otherwise the installation's
profiles in `$PAPAIA_CONFIG_DIR/.env`. A distributed start never takes an exported
`COMPOSE_PROFILES`, neither for the nodes nor here. A profile given with `--profiles` (or exported) that
no compose file of the core declares stops `start` with exit 2. One in `.env` (misspelt, or
dropped by a later release; Compose ignores it) does not: `start` names it and the file
with "remove it or run setup again" and goes on with the others.

Ownership: the services of both sources run as uid 10001 with every capability dropped,
and the key is 0600. When `papaia-ctl` runs as root, it hands the three files to uid 10001
and keeps the folder itself (root, mode 0711): uid 10001 opens the files by name but can
never add, replace or remove an entry, so no link it could plant is ever there for a later
run as root to follow. `audit cert` does the same for these two sources. Run as root, a
client folder that root does not own (or that others may write to) is first taken back
(root, 0700, without following a link) before anything in it is read; a client folder that
is itself a link stops `start` with exit 2. A usable certificate whose files are not handed
over yet is handed over without being replaced (one row, operation
`audit_cert.hand_over`). Run as another account, `start` leaves a folder already handed
over (root's, its key uid 10001's) alone and, on Linux,
warns on every start while the folder belongs to that account and the services cannot read
it: run `start` as root (`sudo tools/papaia-ctl start`). A folder of a third account, such
as the empty one Docker creates as root for a missing bind mount, stops `start` with exit 2
and names it: remove it, or run `start` as root. Docker Desktop's file sharing on macOS does
not enforce the owner, so there nothing is said.

## Files

Under `$PAPAIA_CONFIG_DIR/infra/audit/`:

| Path | Content | Mode |
|---|---|---|
| `pki/ca.key`, `pki/ca.crt` | ingest CA (P-256, 10 years); the key is used by `papaia-ctl` only | dir 0700, key 0600 |
| `service/server.crt`, `server.key`, `ca.crt`, `sources.json`, `token-keys.json` | mounted read-only into `papaia-audit` | key 0600 |
| `secrets/db-owner-password` | Docker secret of `papaia-audit-db` and `papaia-audit-schema` | dir 0700, 0600 |
| `secrets/db-ingest-password`, `db-read-password` | Docker secrets of `papaia-audit-schema` (sets them) and `papaia-audit` (logs in with them) | 0600 |
| `secrets/db-retention-password` | Docker secret of `papaia-audit-schema` (sets it) and `papaia-audit` (retention) | 0600 |
| `secrets/db-hold-password` | Docker secret of `papaia-audit-schema` (sets it) and `papaia-audit` (deletion lock) | 0600 |
| `secrets/heads-signing-key` | Ed25519 key that signs chain heads | 0600 |
| `secrets/pseudonym-key` | key of the pseudonyms of the read API and the SIEM export; never replaced | 0600 |
| `service/siem-ca.crt` | optional CA of the SIEM target | 0644 |
| `heads-target` | the backup target `audit-heads/` was set up on | 0600 |
| `clients/<source>/` | certificate and key of one source | dir 0700 (0711 and root's once handed over), key 0600 |

The database schema, function, triggers and roles are created by `papaia-audit-schema`
from `schema.sql` in the image (`src/infra/audit/papaia_audit/schema.sql`), in one
transaction, when the schema `audit` does not exist yet; `schema_read.sql` adds the person
queries of the read API in the same way when `audit.person_query` does not exist yet, and
`schema_retention.sql` adds retention, deletion lock and export positions when
`audit.anchor` does not exist yet, and `schema_access.sql` adds the role `audit_hold`, the
lock requests and the report confirmations when `audit.legal_hold_request` does not exist
yet (each also on a store of an earlier release). On every start it sets the passwords of
`audit_ingest`, `audit_read`, `audit_retention` and `audit_hold` from their secrets, so a
replaced password takes effect with the next start.
