# Information and erasure without an account

A person whose account is disabled or deleted cannot open the personal area any more, but
the modules still hold data under her `sub`. `papaia-ctl person export` gives her that data
as one encrypted archive; `papaia-ctl person erase` hands over the objects she owns and
erases her data in every module. Both run on the host, as the operator, and need nothing
from the identity service: a deleted account works the same as a disabled one.

The steps for operators, in German, are in
[Auskunft und Löschung ohne Konto](de/betrieb/auskunft-und-loeschung.md).

## Commands

```sh
papaia-ctl person export --sub=<sub> --out=<file> --recipient=<age1...> [--recipient=...]
papaia-ctl person erase  --sub=<sub> --now [--transfer-to=<sub>]
```

| Exit | `person export` | `person erase` |
|---|---|---|
| 0 | every module delivered; the archive is written | every module erased (or kept with a date) |
| 1 | the archive is written, a module is missing; `index.json` names it | partial: a module failed or a transfer failed; the others are named |
| 2 | refused before any module ran (input, declarations, `--out` exists) | refused before any module ran (input, declarations, no erasure journal) |

`--sub` and `--transfer-to` take 1 to 255 characters of `A-Z a-z 0-9 . _ : @ + -`, starting
with a letter or digit. `--transfer-to` must name another person. Both commands run on a
single host installation; in a distributed installation they stop with a message.

Both print one line per row of the records of processing (every `exposes` entry with
`personal_data: true`): `included`, or `not included` with the reason. A row is never left
out. Core services that keep personal data without a module contract (chat, model gateway,
identity service, `papaia-lifecycle`, `papaia-audit`) are listed as not included while
their path for one person is not part of this version; the audit trail is kept on erasure
as evidence.

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
  archive is built in memory and written only encrypted with age to the `--recipient` keys
  (file mode 0600, never over an existing file). Until then the module answers wait in a
  temporary run folder only the operator's account can open (mode 0700), which is removed
  when the command ends. Whoever holds a matching identity can read
  it; hand archive and identity to the person on two separate ways.
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
  `{type: person, id: <sub>}`, the host account as the acting identity, one correlation id
  per run, `detail` with `bytes` or `count` (and the journal `kind` and `seq`), never
  content. The archive write is one more row (`person.export_archive`).

## Backups

An erasure takes effect in the restore points only when they are deleted (by the retention
of `backup --retention-period-days` or `--keep`, or by `backup-delete`). Until then the
erased data is still in the backups. The erasure journal keeps it from coming back:
`restore` and `rollback` run every module's `erasure-replay` before the module starts, so
the entries the modules wrote here are applied again (see
[Wiederherstellung](de/wiederherstellung.md)).

## Not part of this version

- A request with a request id, the confirmation by a second person in the manager with a
  fresh sign-in, `person find` and `person status`, and an archive encrypted to a one-time
  passphrase shown only to the confirming person. Until then the operator runs the commands
  directly and the confirmation of a second person is an organisational step.
- The paths of the core services (chat, model gateway, identity service with the deletion of
  the account last, `papaia-lifecycle`, the pseudonymous extract of the audit trail); they
  are listed as not included.
- The check after erasure that no trace of the `sub` is left outside the listed retention
  duties.
- A central deletion lock in the core; modules report their own (`legal_hold`).
- Distributed installations.
