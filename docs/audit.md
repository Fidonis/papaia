# The audit store

`papaia-audit` is the one place that keeps the audit events of the stack. Every module and
every server writes its events in the format `papaia.audit/1` into a local outbox and
delivers them to `papaia-audit`; nothing else stores or serves audit events. The store is
append-only: one hash chain per source, signed chain heads, and a verification job that
names the first event that no longer fits.

The service is always on (profile `audit`, like the single exit). `papaia-ctl setup` keeps
the profile in `COMPOSE_PROFILES`; `papaia-ctl start` creates the certificates, passwords and
the signing key before the containers start and never replaces existing ones.

Reading and searching events, retention, the SIEM export and the scheduled signing of chain
heads are separate features and not part of this page.

## Containers, networks, ports

| Container | Networks | Purpose |
|---|---|---|
| `papaia-audit` | `papaia-audit-net`, `papaia-audit-ingest-net` | ingest on `:8443` (mutual TLS), `verify`, `heads` |
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
| `service/server.crt`, `server.key`, `ca.crt`, `sources.json` | mounted read-only into `papaia-audit` | key 0600 |
| `secrets/db-owner-password` | Docker secret of `papaia-audit-db` and `papaia-audit-schema` | dir 0700, 0600 |
| `secrets/db-ingest-password`, `db-read-password` | Docker secrets of `papaia-audit-schema` (sets them) and `papaia-audit` (logs in with them) | 0600 |
| `secrets/heads-signing-key` | Ed25519 key that signs chain heads | 0600 |
| `clients/<source>/` | certificate and key of one source | dir 0700, key 0600 |

The database schema, function, triggers and roles are created by `papaia-audit-schema`
from `schema.sql` in the image (`src/infra/audit/papaia_audit/schema.sql`), in one
transaction, when the schema `audit` does not exist yet. On every start it sets the
passwords of `audit_ingest` and `audit_read` from their secrets, so a replaced password
takes effect with the next start.
