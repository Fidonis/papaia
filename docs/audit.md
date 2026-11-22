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
| `papaia-audit` | `papaia-audit-net`, `papaia-audit-ingest-net` (and its egress network while a SIEM target is set) | ingest and read API on `:8443` (mutual TLS), `verify`, `heads`, retention, SIEM export |
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
`papaia.audit/1` schema of the platform kit, schema version 1.3.0 (kit 0.1.2 and the
unreleased delegation lifetime revision); the test suite runs the kit's submission vectors
against the ingest. Revision 1.1.0 adds the optional token time fields `token_iat`,
`token_auth_time` and `token_remaining_s` (integers from 0, or `null`); a value other than
`null` is accepted only in the server's row of an operation (`role` `server`, `event`
`operation`). Revision 1.2.0 adds the events of the erasure journal and their `detail` fields.
Revision 1.3.0 adds the event `delegation_lifetime_changed` and its `detail` fields
`idle_days_old`, `idle_days_new`, `max_days_old`, `max_days_new` (whole days from 1 to
365, all four or none, only in that event, required when the change was allowed); the
core writes it for every change of the delegation lifetime
([configuration.md](configuration.md#delegation-lifetime)), before the settings file; a
change whose file could not be written is followed by a row of the same correlation id with
`result: error` and `error_code: io`. Rows of earlier revisions stay
valid.

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
| `audit_read` | `SELECT` on `audit.event` and on the tables of retention and export |
| `audit_retention` | execute `audit.prune`, and write the retention run's own events (`audit.next_seq`, `audit.append_own`, `audit.setting_put`) — nothing else |
| `audit_owner` | owns the database; its password is a secret of the database container and of `papaia-audit-schema` only |

Triggers refuse every `UPDATE` and `TRUNCATE` on `audit.event`, also for the owner, and
every `DELETE` outside `audit.prune` (see [Retention](#retention)). The owner can switch the
triggers off; such an intervention is not prevented but found by verification.

`audit_ingest` additionally executes the functions that move the SIEM read positions
(`audit.export_targets_set`, `audit.export_advance`). No service role executes
`audit.legal_hold_set` or `audit.legal_hold_lift` (see [Deletion lock](#deletion-lock)).

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
| `papaia-manager` (page "Audit-Log"), `papaia-ctl` | `/v1/events`, `/v1/exports`, `/v1/person-queries…` |
| `papaia-me` (page "Aktivität") | `/v1/me/reads` |

Every request carries the bearer token of a person (`Authorization: Bearer …`), obtained by
token exchange for the audience `papaia-audit`: signed RS256 by the realm, issuer and
audience exact (one audience), not expired, with a session (`sid`; a service account's
token has none). The routes of the audit log further need the realm role
`papaia-auditor`; without it every route answers `403` (`forbidden_or_not_found`). Any
other client or path answers `404`. Errors use the platform's error envelope
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
lifted by two different persons with a reason of 20 to 1000 characters; the database
refuses a lock or a lift confirmed by the person who asked for it. Lock rows are never
deleted, a lift is recorded in the row. Retention already honours locks. Setting and
lifting comes with the person-authenticated API of the store, which takes both persons
from their verified tokens and writes the `legal_hold_set` and `legal_hold_lifted` events
in the same transaction; until then no service role may call `audit.legal_hold_set` or
`audit.legal_hold_lift`, and no host command sets a lock.

## SIEM

`papaia-audit` is the only component that sends audit events out of the stack. Set the
target in the root `.env`:

| Variable | Meaning |
|---|---|
| `PAPAIA_AUDIT_SIEM_TARGET` | `syslog-tls://host[:6514]` (syslog RFC 5424 over TLS RFC 5425, octet counting) or `https://host[:port]/path` (`POST` of up to 500 JSON lines; 2xx means taken). Empty: no export |
| `PAPAIA_AUDIT_SIEM_PEN` | private enterprise number in the structured data, default `32473` (the example number of RFC 5612) |
| `PAPAIA_AUDIT_SIEM_IDENTITY` | `pseudonym` (default) or `sub` |
| `PAPAIA_AUDIT_SIEM_BASIS` | with `sub`: the agreement the clear-text export rests on (required) |

A syslog message carries `APP-NAME` `papaia`, `MSGID` the event name and
`[papaia@<PEN> source="…" seq="…"]`; the message is the event in its stored form (with
`source`, `seq`, `prev_hash`, `hash`). With `pseudonym`, `sub` and person ids in
`object_ref` leave as `P-` and 8 characters of base32(HMAC-SHA-256(key, sub)), with the key
`secrets/pseudonym-key` that never leaves `papaia-audit`, and `client_ip` is left out;
`hash` stays that of the stored event.

The queue is the store: each target keeps a read position per source
(`audit.export_cursor`) that moves only after the target took a batch. After an outage or a
restart the export resumes from there, so an event can arrive twice but is never skipped;
receivers recognise a repeat by `source` and `seq`. Retention keeps events a target has
not taken.

A target that is removed from or replaced in the configuration is no longer sent to, but
it keeps holding back every event it has not taken: removing it is not a decision to
discard them. Only `papaia-ctl audit siem skip` releases them, with a reason recorded as an
event. Until then, retention records such a source as `siem_undelivered`.

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
`papaia-me`, `papaia-manager`, `papaia-lifecycle`, `papaia-egress`, `papaia-audit`,
`mcp-paperless`, `mcp-qdrant`, `mcp-mssql`, `papaia-ctl`. The files land in
`$PAPAIA_CONFIG_DIR/infra/audit/clients/<source>/` (`client.crt`, `client.key` with mode
0600, `ca.crt` to check the server).

## Files

Under `$PAPAIA_CONFIG_DIR/infra/audit/`:

| Path | Content | Mode |
|---|---|---|
| `pki/ca.key`, `pki/ca.crt` | ingest CA (P-256, 10 years); the key is used by `papaia-ctl` only | dir 0700, key 0600 |
| `service/server.crt`, `server.key`, `ca.crt`, `sources.json`, `token-keys.json` | mounted read-only into `papaia-audit` | key 0600 |
| `secrets/db-owner-password` | Docker secret of `papaia-audit-db` and `papaia-audit-schema` | dir 0700, 0600 |
| `secrets/db-ingest-password`, `db-read-password` | Docker secrets of `papaia-audit-schema` (sets them) and `papaia-audit` (logs in with them) | 0600 |
| `secrets/db-retention-password` | Docker secret of `papaia-audit-schema` (sets it) and `papaia-audit` (retention) | 0600 |
| `secrets/heads-signing-key` | Ed25519 key that signs chain heads | 0600 |
| `secrets/pseudonym-key` | key of the pseudonyms of the read API and the SIEM export; never replaced | 0600 |
| `service/siem-ca.crt` | optional CA of the SIEM target | 0644 |
| `heads-target` | the backup target `audit-heads/` was set up on | 0600 |
| `clients/<source>/` | certificate and key of one source | dir 0700, key 0600 |

The database schema, function, triggers and roles are created by `papaia-audit-schema`
from `schema.sql` in the image (`src/infra/audit/papaia_audit/schema.sql`), in one
transaction, when the schema `audit` does not exist yet; `schema_read.sql` adds the person
queries of the read API in the same way when `audit.person_query` does not exist yet, and
`schema_retention.sql` adds retention, deletion lock and export positions when
`audit.anchor` does not exist yet (both also on a store of an earlier release). On every
start it sets the passwords of `audit_ingest`, `audit_read` and `audit_retention` from
their secrets, so a replaced password takes effect with the next start.
