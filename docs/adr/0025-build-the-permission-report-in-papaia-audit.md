---
adr: 0025
title: Build the permission report in papaia-audit with an account that holds view-users only
status: Proposed
date: 2026-11-23
deciders:
  - WilhelmSebastian
tags:
  - security
  - audit
  - keycloak
supersedes: null
superseded_by: null
---

# 0025. Build the permission report in papaia-audit with an account that holds view-users only

## Context

`papaia-ctl report permissions` built the permission report on the host with the master
admin of Keycloak and only asked papaia-audit to release it (`POST /v1/access-reports` with
the row count and the checksum). The manager could not show the report: it has no master
admin, and papaia-audit could not check that the checksum it released belonged to rows it
never saw. A person with `papaia-auditor` should get the report from the manager's audit
page with the same token the audit log uses (token exchange to `papaia-audit`).

The rights Keycloak 26.7.0 needs for the reads of the report were measured against a
throwaway Keycloak with an account in the `papaia` realm (`realm-management` roles):

| Rights held | Result |
| --- | --- |
| none | every read of the report `403` |
| `query-users` | `GET /users` `200` with no user; role mappings, groups and offline sessions `403` |
| `view-users` | users, `role-mappings`, `role-mappings/realm/composite`, `groups`, `offline-sessions/{client}` `200`; `GET /clients` `403` |
| `view-users` + `view-realm` | `GET /clients` still `403` |

With `view-users` alone `GET /admin/realms/papaia` answers, but without the offline-session
settings. A token exchange by `papaia-manager` with the optional scope `aud-papaia-audit`
gave a token with `aud` `papaia-audit`, `azp` `papaia-manager`, `sid` and the person's
roles; another client got `invalid_scope`. A service account's token carries no `sid`.

## Decision

**papaia-audit builds the report.** `POST /v1/access-reports/build` with
`{"by": "person"|"system", "format": "json"|"csv"}` needs the role `papaia-auditor` and a
person's token (with `sid`). papaia-audit reads the realm, builds the report, records the
event `inventory_exported` with the checksum and the row count, and answers with the
report; without the event there is no report. `papaia-ctl report permissions` calls this
route through the host route and prints the answer unchanged; it no longer uses the master
admin. `POST /v1/access-reports` is removed.

**One account with `view-users` and nothing else.** The realm sync keeps the core account
`svc-papaia-audit-report` (profile `audit`): client credentials with an ES256 client
assertion, the key mounted read-only into papaia-audit alone, `realm-management`
`view-users` as its only right and the only role in its token scope; a wider right is
removed on the next sync. papaia-audit sends GET requests only, to the paths of the report
below `/users`; any other path is refused before a request leaves the service.

**What the account cannot read comes from the inputs file.** The realm sync (master admin,
GET only) writes `infra/audit/service/access-report-inputs.json`
(`papaia.access-report-inputs/1`): the module clients with their ids, the service accounts
with owner, deputy, audiences and effects, the confirmed pairings, the emergency account's
id, the offline-session limits, the delegation lifetime and the recertification period. It
holds no secret. The report names the time the file was written (`inputs_written_at`).
Without the file the build answers `503` (`AUDIT-REPORT-INPUTS`) with the hint to run
`papaia-ctl realm sync`.

**One network to Keycloak.** papaia-audit reaches Keycloak on `papaia-audit-idp-net`
(internal, shared with Keycloak alone; communication matrix row K-21) and checks its
certificate against the copy of the local CA that the realm sync puts into the service
folder.

**The exchange to `papaia-audit` is a platform pairing.** `papaia-audit` is an audience for
persons only. The realm sync gives the manager's template client token exchange and the
optional scope `aud-papaia-audit` and removes that scope from every other client;
`security/pairings.yaml` cannot name `papaia-audit`.

## Alternatives considered

- **Keep building on the host and release by checksum.** The manager has no master admin,
  and papaia-audit would keep releasing checksums of rows it cannot check.
- **Give the account `view-realm` and `view-clients`.** The measurement shows that
  `view-realm` does not open `GET /clients`; `view-clients` would let the service read the
  configuration of every client (redirect URIs, mappers, policies) to get a list of ids that
  the realm sync already has. Both widen what a compromised papaia-audit could read.
- **Use the person's exchanged token for the Admin API.** An auditor would need Keycloak
  administration rights, which mixes the audit role with the administration
  (`separation_conflict`).
- **Let the manager build the report.** The manager would need the same rights, and the
  event would be written by a service that is not the audit log.

## Consequences

- `view-users` lets papaia-audit read every user's representation, role mappings, groups and
  offline sessions of the `papaia` realm. That is what the report shows; it is still more
  than the audit log needed before. The key is readable only inside papaia-audit, the
  network reaches Keycloak only, and the client sends GET requests to the report's paths
  only. A compromised papaia-audit can read the realm's users, not change them.
- Changes in clients, pairings or session settings show in the report after the next
  `papaia-ctl realm sync`; the report says when the inputs file was written.
- The kit's naming register does not list `svc-papaia-audit-report` yet; the realm sync
  keeps it as a core account.
