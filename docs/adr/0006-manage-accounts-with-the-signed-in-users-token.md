---
adr: 0006
title: Manage accounts from papaia-manager with the signed-in user's token and give papaia-admin Keycloak's user-administration rights
status: Accepted
date: 2026-10-10
deciders:
  - marko-boehm
tags:
  - keycloak
  - auth
  - roles
  - manager
supersedes: null
superseded_by: null
---

# 0006. Manage accounts from papaia-manager with the signed-in user's token and give papaia-admin Keycloak's user-administration rights

## Context

[ADR 0003](./0003-per-service-admin-roles.md) gave every service its own admin
role under `papaia-admin`. Who may sign in, with which role and from where was
still managed in the Keycloak Admin Console, a second system with a second
sign-in and a technical interface, which is what `papaia-manager` exists to
spare an operator. The manager's Users page covers it: list, create, enable and
disable, roles, passwords and sessions of the realm's accounts.

For that the manager has to reach Keycloak's Admin API, and it has no standing
way to. The `papaia-manager` client has no service account in the realm
template, and the only code that calls the Admin API on a live realm,
`tools/lib/keycloak_role_sync.py`, logs in as the master realm's `admin` with
`KC_ADMIN_PASSWORD`, a credential the manager must not hold.

## Decision

- The manager calls the Admin API with the access token of the signed-in
  account, obtained from the refresh token of its session and kept in memory only.
  It has no credential of its own: no service account, no dedicated API user and
  no new secret to generate on setup or upgrade. Keycloak applies the rights of
  whoever is signed in.
- The rights come from the realm. `papaia-admin` carries `manage-users`,
  `view-users`, `query-users` and `view-realm` of the built-in `realm-management`
  client as client composites. `manager-admin` does not: the Users page is
  reserved for `papaia-admin` (the manager's `MANAGER_IDENTITY_ADMIN_ROLE`, default
  `papaia-admin`), so an administrator of the manager alone cannot manage accounts.
- A fresh install gets the composites from the realm import. An existing realm gets
  them from `keycloak_role_sync`, which reconciles the client-role members of a
  composite the way it already reconciles realm-role members: additive and
  idempotent, it never removes a member, and a client or role it cannot find is a
  warning that does not stop the rest of the sync. It runs on every
  `papaia-ctl start`, which an upgrade ends in.
- No migration: migrations run with the stack stopped and cannot reach the Admin API
  (ADR 0003).
- The realm does not limit what a holder of `manage-users` may grant. `papaia-admin`
  is the highest role in the stack. The manager only protects against locking out
  the last administrator: nobody disables their own account, takes the role from
  themselves or ends all of their own sessions there.

## Consequences

- **Positive**: no standing credential beyond the user's own. Nothing to rotate, and
  the client secret of `papaia-manager` is not widened into a key to the realm's
  accounts. Keycloak decides on every request, so what the page may do is what the
  account may do.
- **Negative**: every `papaia-admin` account can manage accounts, in the manager or
  directly through the Admin API with its own token, and can grant any role,
  `papaia-admin` included. It already had root-equivalent reach through the manager
  (the Docker socket is mounted), so this is no new class of power. A token that
  carries these rights is worth more, so the `papaia-manager` client's redirect URIs
  (`*` in the template) matter more than before.
- **Neutral**: a signed-in `papaia-admin` gets the new rights at the next token
  refresh or sign-in. The roles are Keycloak's own; taking them from `papaia-admin`
  turns the page off and changes nothing else. An installation whose core predates
  this record shows the Users page's "cannot manage users yet" state until the sync
  has run.

## Alternatives considered

- **A service account for the manager's client with `manage-users`** — rejected: a
  long-lived credential with realm-wide user rights next to the login secret, and
  rotating the one would mean rotating the other.
- **A dedicated API user with a generated password** — rejected: one more secret to
  generate on setup and upgrade, to keep in step with Keycloak and to rotate, and the
  manager would act with rights the signed-in person may not have.
- **The rights on `manager-admin`** — rejected: every administrator of the manager
  could then manage accounts and grant any role, including `papaia-admin`.
- **Keycloak's fine-grained admin permissions to limit what `manage-users` may
  grant** — rejected for now: a lot of realm configuration for a role that is the
  highest in the stack anyway. It can be revisited if a lower tier should manage
  accounts.

## References

- [ADR 0003](./0003-per-service-admin-roles.md), per-service admin roles
- `Fidonis/papaia-manager#134`, the Users page
- `Fidonis/papaia#230`, the rights on `papaia-admin`
