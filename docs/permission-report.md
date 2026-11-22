# Permission report, recertification and emergency access

This page covers three operator tasks of the core: the permission report with its
recertification, the emergency account `breakglass`, and the deletion lock set by two
persons. The routes of papaia-audit behind them are described in [audit.md](audit.md).

## Permission report

```sh
papaia-ctl report permissions --by=person --format=json --token-file=- < token
papaia-ctl report permissions --by=system --format=csv  --token-file=/run/user/1000/token
```

The token is the bearer token of the person who asks, for the audience `papaia-audit`
(token exchange, like the manager's audit page). It is read from a file or stdin, never
from the command line, and never printed. The person needs the role `papaia-auditor`;
`papaia-admin` alone is refused (`403`, exit status 3). papaia-audit records every
retrieval as the event `inventory_exported`, the refused ones too, before the report is
printed. Without papaia-audit nothing is printed (exit status 1).

**By person**, one row per account of the `papaia` realm (service accounts are listed under
their own account): realm roles, client roles by client, groups, the service accounts the
person owns or deputises, the stored delegations (offline sessions) by module client,
whether the person holds two of `papaia-admin`, `papaia-auditor` and `papaia-operator`
(`separation_conflict`), and whether it is the emergency account (`breakglass`).

**By system**, one row per audience (catalog entry): the clients with a confirmed exchange
right, their effects and the host accounts that asked for and confirmed it
(`security/pairings.yaml`), and the service accounts with that audience. Rights inside the
target system (Paperless users, Qdrant roles, SQL Server logins) are kept there; the row
says `im Zielsystem geführt`.

Both carry the offline-session limits of the realm and the delegation lifetime in effect.
The report holds no content, no secret and no credential. Objects and approvals inside the
modules (apps, folders, key figures) are reported by the modules themselves.

**Determinism.** Rows are sorted by key. `digest` covers one row's content and `checksum`
the content of all rows and the session limits, but not the confirmation state: two
reports of an unchanged realm have the same checksum, and a role removed from one person
changes exactly that person's row. The JSON form follows
[tools/schemas/access-report.schema.json](../tools/schemas/access-report.schema.json)
(format `papaia.access-report/1`). In the CSV form a cell that a spreadsheet would run as a
formula starts with `'`.

## Recertification

```sh
papaia-ctl report confirm --key=person:<sub> --digest=sha256:<row digest> --token-file=-
```

A person with `papaia-admin` confirms one row with the `digest` the report shows for it;
nobody confirms their own row. papaia-audit stores the confirmation with the event
`approval_changed` (`operation` `access_report.confirmed`). Every report shows per row
`last_confirmed_at` and `confirmation_due`; a row is due when it was never confirmed, when
its last confirmation is older than `PAPAIA_RECERTIFICATION_DAYS` (optional in the root
`.env`, default 180, 30 to 730), or when its content changed since. Confirming the shares
of an app is done by its owner in the module. Exit status: 0 confirmed, 3 refused by
papaia-audit, 1 papaia-audit unavailable, 2 invalid input. A key holds letters, digits and
`. _ : @ + -` after `person:` or `system:`; a `sub` with another character cannot be
confirmed.

## Emergency account

```sh
papaia-ctl breakglass create --address=betrieb@example.org
papaia-ctl breakglass status
papaia-ctl breakglass rotate
```

`create` adds the local account `breakglass` to the `papaia` realm once:

- the password (32 characters) is shown once on the terminal and stored nowhere: not in an
  output stream, a log, an audit row or a file. Without a terminal the command refuses;
- the first sign-in sets up the second factor (`CONFIGURE_TOTP`); every later sign-in asks
  for it;
- rights: administration of Keycloak (`realm-management` `realm-admin`) and of the platform
  (`papaia-admin`), no role of a target system. A realm administrator can give any account
  any role; data rights on this account are detected in the permission report
  (`breakglass: true`), not prevented;
- the e-mail address is the operator address given with `--address`.

The account is local and works while an upstream identity provider is stopped.

papaia-ctl knows the account by its id, which it records with the time of the last
rotation in `security/breakglass/account.json` of the configuration directory (folder
0700, file 0600), not by a user attribute (Keycloak 26 drops attributes its user profile
does not declare). The permission report marks this id only. An account named
`breakglass` with another id is refused by `create`, `rotate` and `status` and never
changed: rename or remove it in Keycloak. The same applies when the configuration
directory lost the record. A `create` that fails after Keycloak added the account removes
the account again; nobody has seen its password.

**Every sign-in** is one audit row `breakglass_login` written by papaia-lifecycle (profile
`lifecycle`), which reads the realm's sign-in events every 10 seconds, and an `ALERT` line
in its log. `breakglass status` shows the last sign-in and reports `rotation_due: true`
from a sign-in until the next `rotate`. `create` and `rotate` are each one audit row
`breakglass_change` without the password. Without the `lifecycle` profile no sign-in is
seen: `create`, `rotate` and `status` then print a warning and `status` reports
`monitored: false`. When the profile is switched on after the account was created, run
`papaia-ctl breakglass status` once: it writes the account's id for papaia-lifecycle.

**Custody, drill and rotation** (for the operating manual):

1. Custody with four eyes: the password and the second factor are kept apart by two
   persons; neither holds both.
2. Drill every six months: sign in with both persons, record date, persons and result,
   then rotate.
3. Rotate after every use: `papaia-ctl breakglass rotate`, then hand the new password over
   as in step 1. Until then `status` flags the account.

## Deletion lock

A deletion lock keeps every audit event of one person past retention. It is set and lifted
through papaia-audit by two different persons with the role `papaia-legal-hold`, each after
a fresh sign-in, with a reason ([audit.md](audit.md#deletion-lock)). One person alone can
neither set nor lift it, whatever the platform's four-eyes setting says, and there is no
host command for it.

`papaia-ctl realm sync` creates the realm role `papaia-legal-hold`, outside the composite
`papaia-admin`. An administrator assigns it in Keycloak to at least two persons. Their
token reaches papaia-audit with the role only through a sign-in client that lists
`papaia-legal-hold` in `visible_for_roles`. The administration (papaia-manager, MGR-007)
does that together with its views for the lock. Until then no person can reach the lock
routes.

## Ordered disclosure about a person

An ordered disclosure of the audit events about one person uses the person filter of the
audit log ([audit.md](audit.md#person-filter-reason-and-a-second-person)): one person with
`papaia-auditor` asks with the reason (the order's reference), a second one confirms after a
fresh sign-in; each read and export is an event, and the affected person sees the reads in
"Mein Bereich → Aktivität". For the data of a person inside the modules there is no product
procedure yet: the module's own export or the database of the module is the remaining way,
under the same two-person rule and with the order recorded.
