# Platform halt

The platform halt stops every write, send and delete of the whole installation with one
command on the host. It is meant for an incident: a compromised account, a run that does
damage, data flowing where it must not. It needs neither Keycloak nor any other service,
and one person can set it at any time.

```sh
tools/papaia-ctl halt set   [--reason=TEXT]      # also: halt on
tools/papaia-ctl halt clear --reason=TEXT        # also: halt off
tools/papaia-ctl halt status [--json]
```

All three take `--config-dir=PATH`. `--reason TEXT` (with a space) works as well.

## What it does

`halt set` writes `$PAPAIA_CONFIG_DIR/state/halt.json`:

```json
{"active": true, "by": "host:ops", "reason": "incident 42", "since": 1790000000}
```

| Field | Content |
|---|---|
| `active` | `true` while the halt is in force, `false` after `halt clear` |
| `since` | when it was set or lifted, seconds since the epoch |
| `reason` | the text given with `--reason` (empty when setting without one), at most 500 printable characters |
| `by` | who set or lifted it: `host:<account>` for the host command |

The file is written to a temporary file in the same folder and renamed into place, so a
reader sees the old or the new file, never a part of one. It lives on the host and
therefore outlasts a restart of every container; setting it works while Keycloak or the
whole stack is down (exit status 0).

The services that act mount the folder `state/` read-only (never the file itself: a
container that mounts a file keeps seeing the old one after the rename). They check the
file before each write, send or delete, each model call, each flow step and each delivery
(one `stat` call, no network) and in addition every 5 s. That gives:

| What | Stopped within |
|---|---|
| writes, sends and deletes | 10 s after the command returns |
| model calls and everything else, the notice in every interface | 60 s |

Reading one's own data stays possible. A file that cannot be read or does not have
exactly the four fields counts as an active halt; no file is no halt.

`render` (part of `setup`, `start` and `upgrade`) creates the folder `state/` with mode
0755; Compose does not create it.

### In the core

The model gateway (LiteLLM) mounts the folder at `/run/papaia-halt` and refuses every
request of every key while the halt is active, chat included, with HTTP 503 and the error
code `platform_halt` and the fixed notice
"Die Plattform ist durch einen Not-Halt angehalten. The platform is stopped by an emergency
halt." No request reaches a model.

### In the modules

Each module (add-on) mounts `${PAPAIA_CONFIG_DIR}/state` read-only and applies the rules
above to its own effects, besides its own kill switch. `tools/lib/halt.py` holds the
reference reader (`HaltWatch`) these rules are tested with.

Not yet covered by the core: the halt does not stop the mail relay's queue, does not narrow
the allow lists of the exit (`papaia-egress`), and does not act per person (sessions and
delegations of one person: deactivate the account, see [lifecycle](./lifecycle.md)).

## Lifting it

`halt clear` needs a reason; without one it is refused (exit status 2) and the attempt is
an audit row. After lifting, waiting runs and reminders continue as each module documents;
a write step that was stopped is never repeated without a new confirmation of the person.

Setting an active halt again, or lifting one that is not active, changes nothing.

## Audit

Setting, lifting and a refused lift are each one `papaia.audit/1` row in the core's audit
outbox `$PAPAIA_CONFIG_DIR/audit/outbox/papaia-ctl.jsonl`, with its own correlation id:

| Action | `operation` | `event` | `result` |
|---|---|---|---|
| set | `halt.set` | `emergency_stop_set` | `allowed` |
| lifted | `halt.clear` | `emergency_stop_lifted` | `allowed` |
| lift without a reason | `halt.clear` | `emergency_stop_lifted` | `denied`, `error_code: reason_required` |

`writer` is `papaia-ctl/halt`, `sub` the host account (`host:<account>`), `identity_kind`
and `azp` are empty: the host acted, no identity of the realm. The reason text is never
part of a row.

Setting the halt does not wait for the outbox: the file is written first, the row follows
(a running `realm sync` may hold the outbox for up to 120 s). If the row cannot be
written, the command says so, exits with status 1 and the halt stays in force. Lifting
waits for the outbox first and changes nothing when the row cannot be written.

## Backup and restore

`backup` leaves `state/` out of the archive of the configuration directory, and `restore`
keeps the folder as it is on the host: a restore point neither lifts nor sets the halt.

## Limits

- The command is not available in a distributed installation yet.
- Root on the host can change or remove the file; neither its mode nor the audit row
  protects against that.

## Write lock of an upgrade

`papaia-ctl upgrade` puts a second file into the same folder: `state/write-lock.json`, present
from restore point R0 until the upgrade's finish stage (see the README, `upgrade`). Unlike the
halt it only stops writes; reads, sign-ins and model calls go on.

```json
{"active": true, "from": "1.8.0", "message": "The installation is being updated. Your change was not saved. Please try again once the update has finished.", "schema": "papaia.write-lock/1", "since": 1790000000, "to": "1.10.0", "upgrade_id": "0b9a4c0e-8d47-4b0a-9a51-1f2c3d4e5f60"}
```

A reader checks it like the halt file: before each write, one stat call, the file parsed only
when it changed. While it is active the write is refused with `message`, and nothing is
stored. A missing file is no lock; a file that cannot be read, is not a regular file, is
larger than 64 KiB or does not have exactly these fields with `schema` `papaia.write-lock/1`
counts as an active lock (fails closed). The reference reader is `read_lock` in
`tools/lib/upgrade_stages.py`.
