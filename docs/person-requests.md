# Information and erasure without an account

A person whose account is disabled or deleted cannot open the personal area any more, but
the modules still hold data under her `sub`. `papaia-ctl person export` gives her that data
as one encrypted archive; `papaia-ctl person erase` hands over the objects she owns and
erases her data in every module. Neither runs at once: each files a request with a request
id, a second person confirms it in the manager after a fresh sign-in, and only then
`papaia-ctl person run <request>` runs it on the host, as the operator. The run needs
nothing from the identity service: a deleted account works the same as a disabled one.

The steps for operators, in German, are in
[Auskunft und Löschung ohne Konto](de/betrieb/auskunft-und-loeschung.md).

## Commands

```sh
papaia-ctl person find   --name=<user name> | --email=<mail address>
papaia-ctl person export --sub=<sub> --requested-by=<sub> --confirmed-by=<sub>
papaia-ctl person erase  --sub=<sub> --now --requested-by=<sub> --confirmed-by=<sub> [--transfer-to=<sub>]
papaia-ctl person status   <request>
papaia-ctl person run      <request>
papaia-ctl person handover <request>
papaia-ctl person sweep
```

| Command | Does | Exit |
|---|---|---|
| `find` | the `sub` of a person by user name or mail address, also of a deleted account ([below](#find-a-person)) | 0 (also when nobody is found), 2 refused |
| `export`, `erase` | files a request in `papaia-audit` and prints its id; nothing runs | 0 filed, 2 refused |
| `status` | the request's state | 0, 2 unknown request |
| `run` | runs a confirmed request | 0 done; 1 partial (`export`: the archive is written, a module is missing and `index.json` names it; `erase`: a module or a transfer failed, the others are named); 2 refused before any module ran (request not confirmed, expired or already run, input, declarations, no erasure journal) |
| `handover` | deletes the archive of an export once it is handed over | 0, 2 |
| `sweep` | deletes every archive older than 14 days (every `person` command does this first) | 0 |

`--sub`, `--requested-by`, `--confirmed-by` and `--transfer-to` take 1 to 255 characters of
`A-Z a-z 0-9 . _ : @ + -`, starting with a letter or digit. `--requested-by` is the person
who files the request, `--confirmed-by` the second person who confirms it; they must
differ. `--transfer-to` must name another person than `--sub`. `run` works on a single host
installation; in a distributed installation it stops with a message.

## Requests and confirmation

`papaia-audit` keeps the requests (`audit.person_request`, never deleted) next to the audit
trail, so the request, its confirmation and every module call share one store and one
correlation id: the request id.

| State | Label in `person status` | Next |
|---|---|---|
| `open` | offen (wartet auf Bestätigung) | confirmed or rejected in the manager within 7 days |
| `confirmed` | bestätigt (bereit für person run) | `person run` within 24 hours |
| `rejected` | abgelehnt | — |
| `running` | läuft | the run ends with `done` or `partial` |
| `done` | erledigt | — |
| `partial` | teilweise | file a new request after the failure is fixed |
| (open after 7 days, confirmed after 24 hours) | abgelaufen | file a new request |

1. **File.** `person export|erase` sends the request to `papaia-audit` through
   `docker exec` (the host route has no network path and no token; it accepts only
   creating, reading and running requests, never a confirmation). The event
   `person_request_created` (writer `papaia-audit/person`, `sub` = `--requested-by`,
   `object_ref` `{type: person_request, id}`) is stored in the same transaction.
2. **Confirm.** The person named by `--confirmed-by` opens the request in the manager and
   confirms or rejects it: `GET /v1/person-requests` lists the requests of the last 7 days
   that name the signed-in person (at most 200), `POST /v1/person-requests/<id>/confirm|reject` decides.
   Only `papaia-manager` reaches these routes, with the person's token (audience
   `papaia-audit`) and the realm role `papaia-confirm` or `papaia-admin`. A confirmation
   needs a sign-in of at most 5 minutes ago (`AUDIT-AUTH-FRESH`). The requesting person
   cannot confirm her own request (`403`, `AUDIT-PERSON-REQ-SELF`, a `denied` event); the
   database refuses it as well. Either of the two may reject. A request the signed-in person
   is not named in answers `404`. Events: `person_request_confirmed`,
   `person_request_rejected`.
3. **Passphrase.** Confirming an export shows the confirming person a passphrase once
   (8 groups of 5 characters, 200 bits). `papaia-audit` keeps only the scrypt key derived
   from it (salt, work factor 2^16, 32 bytes) and never the passphrase. The confirming person
   hands it to the person concerned on another way than the archive.
4. **Run.** `person run <request>` checks that the request is confirmed and not older than
   24 hours, marks it `running`, runs every module, takes the archive key once (it is
   removed as it is read) and records `done` or `partial`; each step is an `operation` row
   (`person_request.<operation>.start`, `.key`, `.finish`). A request runs once.

## The archive folder

The archive of an export is written to `<config-dir>/state/person-export/<request>.zip.age`
(folder mode 0700, file mode 0600, never over an existing file), encrypted with age to the
passphrase of the confirmation (age's scrypt recipient; `age -d` opens it with the
passphrase). A record next to it holds the time it was written. The archive leaves the host
by the operator's way of choice; after the hand-over

```sh
papaia-ctl person handover <request>
```

deletes it. Every archive is deleted 14 days after it was written: every `person` command
sweeps the folder first, and `papaia-ctl person sweep` does so alone (for a timer).
`doctor person_export` warns while an archive waits and fails for one older than 14 days.
Each deletion is one audit row (`person.export_handed_over` or `person.export_expired`).
`state/` is not part of the backup.

## Find a person

A deleted account leaves nothing in the identity service to look up its `sub`.
`papaia-lifecycle` keeps an index of the persons it sees (members of `papaia-persons`): the
HMAC-SHA256 of the installation key `erasure-hmac` over the user name and over the mail
address (Unicode NFKC, outer blanks removed, case folded), the account state and the day of
the last sign-in. When an account is deleted, its two HMACs move to the tombstones with the
day of the deletion. Neither holds a clear name or address.

`person find` hashes its input on the host the same way and asks `papaia-lifecycle`
(through `docker exec`) for matching entries. It prints at most 20 persons with `sub`,
status (`active`, `disabled`, `deleted`) and days, never a name. One audit row
(`person.find`, `detail.count`) per search; the input is not logged. It needs the lifecycle
profile.

**Name lock.** When an account appears with the user name or mail address of a deleted
account, `papaia-lifecycle` disables it once (`lifecycle.account_name_locked`, an `ALERT`
line), so a new person cannot take over the old one's data by name. An administrator who
checked the case enables the account again; the service does not disable it a second time.

## Output of a run

`person run` prints one line per row of the records of processing (every `exposes` entry with
`personal_data: true`): `included`, or `not included` with the reason. A row is never left
out. Chat, model gateway and identity provider are included through the core paths
([below](#the-core-services)); `papaia-lifecycle` (its tombstone stays as long as the
erasure journal), `papaia-audit` (the audit trail is kept on erasure as evidence) and the
contents of uploaded chat files are listed as not included, with the reason.

## The core services

Chat, model gateway and identity provider keep personal data without a module contract.
The core brings one export and one erasure path for each; the operator never reaches into
a database. Each path runs where its service runs, through `docker exec`:

| Service | Export | Erasure | Path |
|---|---|---|---|
| Chat (`core-chat`) | the chat accounts whose OIDC id is the `sub` (name, user name, mail, provider, times), conversations, messages, file records, presets, prompts, shared links, tags, tool calls, memories, balances and transactions | all of these, plus stored keys, plugin settings, tokens and sessions, then the accounts | a `mongosh` script in the chat database container. It creates a role and a login for this one call (read only for an export, find and remove for an erasure, on the chat's collections only), signs in with it and drops both before it ends. The password is made for the call and lives only in memory and on the script's standard input |
| Model gateway (`model-gateway`) | the usage sum (`spend`) of every end user that is the `sub`, a chat account id of the person or her mail address | those end users | the gateway's management API inside its container: `GET /customer/info`, `POST /customer/delete` (the gateway's per-request spend-log rows are not touched; they keep counts, never content, see [model-gateway.md](model-gateway.md)) |
| Identity provider (`identity`) | the account (user name, name, mail, attributes, state, creation), groups, realm roles, linked upstream identities, consents (no tokens), stored sign-in events (time, type, client, address) | the account, last | `papaia-lifecycle`'s command `person` as `svc-papaia-lifecycle`, the one account that may end sessions and delete persons; no other account gets these rights |

Stored keys, plugin settings, tokens and sessions of the chat are sign-in material, not data
about the person: they are erased, never exported. A `sub` that cannot be an id of the
identity provider has no account there.

**Order of an erasure.** First the account is disabled and its sessions and consents end
(`person.identity_revoke`); then the transfers, the modules, the chat and the gateway; the
core writes the journal entries `core-chat` and `model-gateway` (`erase_subject`,
`object_ref` `person_request:<request>`, the person as `subject_ref` only); the account is
deleted last (`person.identity_delete`). The running `papaia-lifecycle` journals the
deactivation and the deletion in `identity` from their admin events and keeps the
tombstone. When any step before fails, the account is not deleted: it stays disabled, the
request ends `partial`, and the `sub` stays assigned for a new request. A failed transfer
stops every erasure, in the core as in the modules.

**Reconciliation (governance GV-30 for the core services).** After an erasure the core
asks chat, gateway and identity provider once more for anything that still names the
person: chat documents filed under her accounts, chat accounts with her `sub` or mail
address, gateway end users with her `sub`, account id or mail, her account. The output
names the place and the number, never content (`left core-chat/chat_messages: 2`). Every
find, and every service that cannot be asked, makes the request `partial`. One audit row
`person.reconcile` with the number of finds.

**Audit.** Every call of a core path is one row with the request id as the correlation id:
`person.export` (`detail.bytes`), `person.identity_revoke` and `person.identity_delete`
(`detail.count`), one `person.erase` row per chat collection or gateway kind
(`detail.objects`, `count`, the journal `kind` and `seq`), and `person.reconcile`. A failed
call is a row with `result: error` and a code (`backend_failed`, `not_running`,
`invalid_answer`, `journal_failed`).

**Content in the gateway.** `doctor model_gateway_content` fails when the rendered gateway
configuration would keep request or response content (prompts in the spend logs, message
logging, a logging callback, a response cache, the log level `DEBUG`): the usage the core
exports and erases must not hold any.

## The module side (contract generation 15)

A module takes part by declaring the reserved actions under `actions:` and
`requires.addon_api: 15`:

```yaml
actions:
  person-export: {service: migrate, args: ["person-export"]}
  person-erase: {service: migrate, args: ["person-erase"]}
  transfer-ownership: {service: migrate, args: ["transfer-ownership"]}
```

The core runs each as `docker compose run --rm -T <service> <args>` in the module's own
project, with the files and env files of `addon start` and standard input closed. Neither `addon run` nor `restore` runs these actions. The step gets:

| Variable | Value |
|---|---|
| `PAPAIA_PERSON_SUB` | the person |
| `PAPAIA_PERSON_OPERATION` | `export`, `erase` or `transfer` |
| `PAPAIA_NEW_OWNER_SUB` | the new owner (only for `transfer-ownership`) |
| `PAPAIA_CORRELATION_ID` | the id of the run; the module's own audit rows carry it |

Exit code 0 means done; any other code counts as failed. The answer is the step's standard
output; logs go to standard error and never carry content.

- **`person-export`** prints one JSON object of at most 100 MiB: the same answer the module
  gives the personal area for `data.export` (personal-area contract v2), in the shape of its
  exit export schema (`exposes[].export.exit.schema`).
- **`transfer-ownership`** hands every object the person owns to the new owner, as the
  module's `transfer_ownership` does for the manager: objects with a write action need a new
  approval by the new owner and a second person; a module refuses a new owner that is not an
  active person (exit code other than 0). It prints `{"transferred": <n>, "halted": <n>}`.
- **`person-erase`** erases the person's data, writes its erasure journal through the
  module's journal writer (`erase` or `erase_subject` entries) and prints a receipt that
  names every declared category of the module once:

  ```json
  {"categories": [
     {"id": "tasks", "state": "done", "deleted": 4},
     {"id": "time_records", "state": "kept", "until": "2028-12-31", "reason": "legal_obligation"}
   ],
   "journal": [{"id": "8a1f…", "seq": 17}]}
  ```

  `kept` means the data stays until `until` (a date): `legal_obligation` for a retention
  duty, `legal_hold` for a deletion lock, which takes precedence and is reported. Repeating
  the step must be harmless (`deleted: 0` once nothing is left).

A receipt with other fields, another set of categories, a negative count or a date that is
not a date counts as a failed module.

## What the core checks and keeps

- **Archive.** `person export` packs the answers in the format of the personal area's
  export: `index.json` (`created_at`, `installation`, `modules[]` with `module`, `title`,
  `contract_version`, `status` `ok|truncated|unavailable`, `file`, `schema`, `bytes`, and
  `not_connected[]` with the rows not included and their reason), `<module>.json` unchanged,
  `<module>.schema.json` when the schema is a file of the module, and `LIESMICH.txt`. The
  archive is built in memory and written only encrypted (see
  [The archive folder](#the-archive-folder)). Until then the module answers wait in a
  temporary run folder only the operator's account can open (mode 0700), which is removed
  when the command ends. Whoever holds the passphrase can read the archive; hand archive
  and passphrase to the person on two separate ways.
- **Transfer before erasure.** With `--transfer-to`, every module that declares
  `transfer-ownership` hands over first. If one transfer fails, nothing is erased.
- **Erasure journal.** `person erase` needs the installation key `security/erasure-hmac` and
  the journal folder `$PAPAIA_BACKUP_DIR/erasure-journal` (the lifecycle profile creates
  both); without them it refuses before any module runs, because an erasure without a journal
  entry would come back with the next restore. For every entry the receipt names, the core
  reads the module's journal at the backup target and checks module, kind and
  `subject_ref` (HMAC-SHA256 of `erasure-hmac` over the `sub`). A module that deleted data
  without naming an entry, or names an entry of another person, fails (`partial`). An entry
  that is not yet at the backup target (the module buffers it while the target is
  unreachable) is reported as pending; the module's own health check shows it until it is
  delivered.
- **Proof.** The output lists per module and category the number erased and whether the
  journal entry is at the backup target, or the date until which data is kept and why.
- **Audit.** Every module call is one `papaia.audit/1` row in the core's audit outbox
  (writer `papaia-ctl/person`): operation `person.export`, `person.transfer_ownership` (event
  `ownership_transferred`) or `person.erase`, the module's catalog entry, `object_ref`
  `{type: person, id: <sub>}`, the host account as the acting identity, the request id as
  the correlation id, `detail` with `bytes` or `count` (and the journal `kind` and `seq`), never
  content. The archive write is one more row (`person.export_archive`).

## Backups

An erasure takes effect in the restore points only when they are deleted (by the retention
of `backup --retention-period-days` or `--keep`, or by `backup-delete`). Until then the
erased data is still in the backups. The erasure journal keeps it from coming back:
`restore` and `rollback` run every module's `erasure-replay` before the module starts, so
the entries the modules wrote here are applied again (see
[Wiederherstellung](de/wiederherstellung.md)).

## Not part of this version

- The manager page that lists and confirms requests and shows the passphrase; until it is
  there, the manager calls the routes above.
- The pseudonymous extract of the audit trail and the entries of `papaia-lifecycle`; they
  are listed as not included.
- The contents of uploaded chat files on the chat's file volume and the chat's search
  index (the file records are erased); listed as not included.
- The reconciliation over every volume, log and backup (governance GV-30 in full); the
  reconciliation after an erasure covers the core services.
- A central deletion lock in the core; modules report their own (`legal_hold`).
- Distributed installations.
