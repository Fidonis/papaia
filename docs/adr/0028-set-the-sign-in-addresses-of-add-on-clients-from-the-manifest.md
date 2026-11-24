---
adr: 0028
title: Set the sign-in addresses of add-on clients from the manifest
status: Proposed
date: 2026-11-24
deciders:
  - WilhelmSebastian
tags:
  - addons
  - identity
  - security
supersedes: null
superseded_by: null
---

# 0028. Set the sign-in addresses of add-on clients from the manifest

## Context

The realm sync creates the clients an add-on owns in the names register and registers
their public keys (`client_keys`), but it sets none of their sign-in addresses: redirect
URIs, web origin, post-logout redirects and back-channel logout. Realm hardening only checks
the addresses a client already has and keeps those with a fully named host.

An add-on holds no realm token in the stack, and must not get one: an account with write
access to the Admin API could change every client of the realm. So an administrator entered
the addresses by hand (papaia Flow's console client), which breaks installation without
manual work, and a client of an add-on could not get the exact callback a silent sign-in
needs (Flow's engine client for a test run). Addresses entered by hand also drift: nothing
removes one that is no longer used, and a wildcard entry is easy to type.

## Decision

Contract generation 18 adds the optional manifest key `client_addresses`:

```yaml
requires:
  addon_api: [18]
integration:
  nginx:
    - {host_key: console, service: flow-console, port: 8080}
client_addresses:
  - client: flow-console
    host_key: console
    redirects: [/auth/callback]
    post_logout: [/]
    backchannel_logout: /auth/backchannel-logout
    web_origin: true
```

- **The core sets them.** `papaia-ctl realm sync`, which already holds the only account
  that manages clients, puts the public URL the installation gives the interface
  `host_key` (scheme, host name and port of the edge, `lib/ingress.py`) in front of every
  path and sets exactly these addresses: `redirectUris`, `webOrigins` (the host, only with
  `web_origin: true`), `post.logout.redirect.uris` and `backchannel.logout.url`. It marks
  the client with `papaia.sign-in-addresses=declared`. Realm hardening takes the declared
  addresses as the client's configured hosts, so a later run keeps them and removes every
  other entry.
- **Only what is declared.** A second run changes nothing. A path the manifest no longer
  declares is removed; when the entry or the key goes, or the add-on is removed or disabled,
  every address of the marked client goes with the marker. `addon uninstall` deletes the
  client itself (lib/uninstall_journal.py). A client without the key is treated as before.
- **Only exact paths on the add-on's own host.** The manifest names paths, never a host:
  the host is the one of the add-on's own `integration.nginx` entry. A path is absolute and
  exact: no wildcard, query, fragment, `..`, `.` or empty segment (`//`), no percent-encoding
  (it could hide `..`), at most 255 characters. At most 8 entries, 8 redirects and 8
  post-logout paths per client.
- **Only the add-on's own confidential clients.** The client is registered in the names
  register with the add-on as owner and signs persons in with credentials: a client of the
  core (`papaia` or a core profile), a client of another module, a public client (no
  credentials: a redirect is all that protects it), a bearer-only or an exchange-only
  client (they sign nobody in) is refused.
- **Refusals.** `compat` reports a malformed manifest naming the entry (`ERROR`, which
  neither `--force` nor warn mode lets through); the realm sync refuses the same
  declaration before any write (exit 2, nothing changed). The `kritis` security profile
  refuses a plain-http edge. Without host names (`no_proxy`) the client gets no address and
  the run notes it.
- **Older cores.** `GENERATION_FEATURES["client_addresses"] = 18`: a core whose window ends
  below 18 reports the add-on `INCOMPATIBLE`. A core from before this generation does not
  know the key; forced there, it installs the add-on without addresses, so nobody can sign
  in at its clients (it fails closed, nothing is widened).

## Consequences

- An add-on whose clients need sign-in addresses installs without a manual entry in the
  realm, and the realm holds no address of it that the manifest does not declare
  (FLO-44-A1, FLO-44-A5, PLT-21-A1).
- Keycloak refuses any `redirect_uri` that is not one of the declared exact URLs
  (PLT-21-A2); no add-on can widen another client's or the core's addresses.
- No add-on gets a realm token, a new account, a scope or a role. Every change is one
  `papaia.audit/1` row of the realm sync (`realm_sync.harden_client`).
- An add-on that needs a callback on another host cannot declare it; that host would have
  to be an interface of the add-on itself.

## Alternatives considered

- **Give the add-on a realm token or an account that may manage its own clients.**
  Keycloak's fine-grained admin permissions do not limit an update to the address fields of
  one client; the account could change scopes, mappers and the authenticator. Rejected.
- **Let the manifest name full URLs.** An add-on could then name a foreign host and receive
  the codes of its sign-ins there. Rejected; the core names the host.
- **Allow a wildcard at the end of the path**, as realm hardening tolerates for the realm
  template's clients. A wildcard admits every path below it, including an open redirect of
  the add-on. Rejected; exact paths only.
- **Leave the addresses to the administrator** with a checklist. That is the manual step
  this decision removes, and it leaves stale addresses behind.

## References

- `tools/lib/client_addresses.py`, `tools/lib/realm_sync.py`, `tools/lib/realm_hardening.py`
- [`docs/client-addresses.md`](../client-addresses.md)
- ADR 0023 (add-on ingress and delivery, the host scheme), ADR 0018 (identity)
