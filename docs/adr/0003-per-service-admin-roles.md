---
adr: 0003
title: Split the shared admin realm role into per-service roles under papaia-admin
status: Accepted
date: 2026-09-18
deciders:
  - marko-boehm
tags:
  - keycloak
  - auth
  - roles
supersedes: null
superseded_by: null
---

# 0003. Split the shared admin realm role into per-service roles under papaia-admin

## Context

Most role-gated services in the stack checked the same flat Keycloak realm
role, `admin` — LiteLLM's `GENERIC_ROLE_MAPPINGS_ROLES` and papaia-manager's
`MANAGER_ADMIN_ROLE` default both hardcoded it. There was no way to make
someone an administrator of one service without making them an administrator
of every service that read that role.

LibreChat had no admin-role concept wired up at all: `OPENID_REQUIRED_ROLE`
shipped empty, so login wasn't even gated by role, despite the pinned
LibreChat version (`v0.8.7`) supporting both a login-gate role
(`OPENID_REQUIRED_ROLE`) and a separate admin-elevation role
(`OPENID_ADMIN_ROLE`).

The NPM admin UI had no role restriction either — any authenticated realm
user could reach the full Nginx Proxy Manager admin UI, which is host-level
reverse-proxy configuration.

## Decision

- Each core service that supports role-gated access gets its own realm
  role: `librechat-admin`, `litellm-admin`, `manager-admin`, `npm-admin`.
  `librechat-user` is a separate login-gate role, since LibreChat's
  `OPENID_REQUIRED_ROLE` is checked independently of `OPENID_ADMIN_ROLE`.
- `papaia-admin` is a composite role bundling every per-service admin role
  (plus `localai-access`, see below). Keycloak's realm-role protocol mapper
  expands composites into the token's `roles` claim, so granting
  `papaia-admin` alone satisfies every downstream per-service check — the
  granular roles stay independently assignable for narrower access.
- `librechat-admin` composites `librechat-user`, so an admin isn't locked
  out of LibreChat login by the new required-role gate.
- LocalAI gets no `localai-admin` role: its actual admin-promotion code path
  (`core/http/auth/` in the LocalAI project) is hardcoded to a single email
  (`LOCALAI_ADMIN_EMAIL`) or "first user becomes admin" — it reads no OIDC
  role or group claim, so a `localai-admin` realm role would be a no-op.
  `papaia-admin` composites in the existing `localai-access` role instead,
  so a papaia-wide admin at least gets SSO login to LocalAI.
- The NPM admin UI is restricted via `--allowed-group=npm-admin` on the
  `nginx-proxy-manager-auth` sidecar. oauth2-proxy's generic `oidc` provider
  silently ignores `--allowed-role`; only `--allowed-group` works, and it
  reads a `groups` claim — so the `oauth2-proxy` client gets a second
  protocol mapper emitting the same realm roles under `groups` (the `roles`
  mapper stays, for anything already consuming it).
- `MANAGER_USER_ROLE` keeps its default (`user`, the realm's default role
  for every account) — only `MANAGER_ADMIN_ROLE`'s default changes, to
  `manager-admin`.
- **Existing installations, not just fresh ones:** Keycloak's
  `--import-realm` only fires on a realm that doesn't exist yet, so the
  template change alone never reaches an already-imported realm.
  `tools/migrations/` cannot fill that gap either — those scripts run with
  the stack stopped (see `tools/migrations/README.md`), before Keycloak is
  back up, so they cannot call its Admin API. Instead, `tools/lib/
  keycloak_role_sync.py` — modeled on the already-wired
  `tools/lib/npm_provision.py` pattern (poll the freshly-started service,
  provision idempotently) rather than the never-invoked client-sync logic in
  `src/infra/keycloak/bootstrap.sh` — runs on every `papaia-ctl start` when
  `AUTH_PROVIDER=internal_keycloak`. It additively creates any missing role,
  composite edge or protocol mapper, and grants `papaia-admin` to every
  account that already held the old flat `admin` role, without touching or
  removing `admin` itself.

## Consequences

- **Positive**: administrators can be scoped per service; LibreChat gets a
  real login gate and admin role for the first time; the NPM admin UI is no
  longer open to any authenticated user; existing installations pick up the
  new roles and the `admin` → `papaia-admin` migration automatically on the
  next start, with no manual Keycloak console work required.
- **Negative**: the old `admin` role is left in place indefinitely rather
  than removed — it's no longer read by any core service, but nothing
  deletes it, since a Keycloak sync step deleting a role or a user's role
  grant is exactly the kind of destructive action this design avoids.
  Operators who want it gone must remove it by hand.
- **Neutral**: `localai-admin` was deliberately not created; if a future
  LocalAI release adds OIDC-role-based admin promotion, this decision should
  be revisited.

## Alternatives considered

- **Keep the flat `admin` role.** Rejected — this is the inflexibility the
  decision exists to fix.
- **Migrate roles via `tools/migrations/`.** Rejected — those scripts run
  with the stack stopped, so they cannot reach the Keycloak Admin API.
- **Fold the new sync logic into `bootstrap.sh`.** Rejected for this change
  — that script's existing client-sync logic is not invoked by `papaia-ctl`
  anywhere today, so building on it would mean *also* wiring it in for the
  first time. A larger, separate change; tracked as a follow-up rather than
  bundled here.
- **Leave the NPM admin UI unrestricted.** Rejected — it's the same class of
  problem (a shared "admin" surface with no per-service role), and the fix
  is small once the `groups` mapper exists for other reasons.
- **Invent a `localai-admin` role.** Rejected — LocalAI has no OIDC
  role/group-based admin promotion to wire it into; it would be a no-op.

## References

- `src/infra/keycloak/README.md` — Realm Roles table
- `Fidonis/papaia-manager` — companion change renaming `MANAGER_ADMIN_ROLE`'s
  own default
