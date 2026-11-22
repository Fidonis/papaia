# The audit store

`papaia-audit` is the one place that keeps the audit events of the stack. Every module and
every server writes its events in the format `papaia.audit/1` into a local outbox and
delivers them to `papaia-audit`; nothing else stores or serves audit events. The store is
append-only: one hash chain per source, signed chain heads, and a verification job that
names the first event that no longer fits.

The service is always on (profile `audit`, like the single exit). `papaia-ctl setup` keeps
the profile in `COMPOSE_PROFILES`; `papaia-ctl start` creates the certificates, passwords and
the signing key before the containers start and never replaces existing ones.

Reading is described under [Reading](#reading). Retention, the SIEM export and the scheduled
signing of chain heads are separate features and not part of this page.

## Containers, networks, ports

| Container | Networks | Purpose |
|---|---|---|
| `papaia-audit` | `papaia-audit-net`, `papaia-audit-ingest-net` | ingest and read API on `:8443` (mutual TLS), `verify`, `heads` |
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
| `audit_read` | `SELECT` on `audit.event` |
| `audit_owner` | owns the database; its password is a secret of the database container and of `papaia-audit-schema` only |

Triggers refuse every `UPDATE`, `DELETE` and `TRUNCATE` on `audit.event`, also for the
owner. The owner can switch the triggers off; such an intervention is not prevented but
found by verification.

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
| `secrets/heads-signing-key` | Ed25519 key that signs chain heads | 0600 |
| `secrets/pseudonym-key` | key of the pseudonyms of the read API; never replaced | 0600 |
| `clients/<source>/` | certificate and key of one source | dir 0700, key 0600 |

The database schema, function, triggers and roles are created by `papaia-audit-schema`
from `schema.sql` in the image (`src/infra/audit/papaia_audit/schema.sql`), in one
transaction, when the schema `audit` does not exist yet; `schema_read.sql` adds the person
queries of the read API in the same way when `audit.person_query` does not exist yet (also
on a store of an earlier release). On every start it sets the
passwords of `audit_ingest` and `audit_read` from their secrets, so a replaced password
takes effect with the next start.
