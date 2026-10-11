---
adr: 0007
title: Offer outbound mail as an optional core profile with one internal SMTP relay
status: Accepted
date: 2026-10-11
deciders:
  - marko-boehm
tags:
  - mail
  - smtp
  - keycloak
  - core
  - addon-contract
supersedes: null
superseded_by: null
---

# 0007. Offer outbound mail as an optional core profile with one internal SMTP relay

## Context

Nothing in the stack can send mail. The Keycloak realm template has no `smtpServer`
and keeps `resetPasswordAllowed` and `verifyEmail` off, and no variable holds a mail
server. Keycloak cannot send a password-reset mail, the "email a link" choice on the
Users page of `papaia-manager` stays disabled because the realm has no mail server, and
anything that wants to send mail later (alerting, notifications, add-ons such as
Paperless-ngx or n8n) would have to invent a mail configuration of its own.

There are two ways to give the stack a mail server. Every service can carry the
provider's SMTP settings, or one service can hold them and the others can send to it.
The first has costs that grow with every consumer:

- The provider password is copied to each place that needs it: the root `.env`, the
  Keycloak realm JSON, where it is a plain string substituted into the template without
  JSON escaping, and the `.env` snapshot of every add-on.
- Every consumer needs outbound access to the provider, and a rotation touches all of
  them.
- A service that talks to the provider directly loses the mail if the provider is down
  at that moment. Keycloak, for one, only reports the failure to the user.

## Decision

- Outbound mail is the **optional Compose profile `smtp`** (`src/infra/smtp-relay/`,
  module label `papaia-smtp-relay`), off by default. It holds one service,
  `smtp-relay`, configured once. The relay holds the credentials of the real mail
  server (the "upstream") and forwards to it; everything else sends to
  `smtp-relay:587` without a login and without TLS inside `papaia-net`.
- The relay is Postfix in the `boky/postfix` image, pinned to an exact tag of its
  Alpine variant. Everything specific to that image sits in the module's compose file
  and in `tools/lib/smtp.py`, so another relay later changes those two files and
  nothing else.
- Only the Keycloak realm is wired in this change. A new realm gets the mail server
  from the rendered realm file (`render_core.bake_realm_secrets` adds the block to the
  parsed template, because a placeholder substitution cannot leave an object out). An
  existing realm gets it from `keycloak_role_sync`, which sets it when the realm has none
  and corrects a block the relay owns. A mail server an operator configured is never
  overwritten, and switching the profile off clears only a block that points at the
  relay. Switching it on also turns on `resetPasswordAllowed`, once.
- The upstream's host, port, security (`starttls`, `tls` or `none`), login and the
  sender address live in the module's own env file. The password does not: setup writes
  it to `$PAPAIA_CONFIG_DIR/infra/smtp-relay/upstream-password` (mode 0600), and the relay
  reads it from there. A non-interactive setup takes it from `PAPAIA_SMTP_PASSWORD`,
  never from an argument. Setup raises `SMTP_RELAY_PASSWORD_REV` whenever the password
  changes, because the file is read once at start and Compose recreates a container only
  when its configuration changes.
- Credentials never travel unencrypted. `starttls` and `tls` verify the upstream's
  certificate against the system CAs, and setup refuses a login together with `none`.
- The relay accepts mail only from the private ranges Docker hands out (`mynetworks`) and
  only for senders in the domain of the configured sender address. It publishes no port.
- The service becomes attachable. `ADDON_API` goes from 2 to 3 (additive, see
  [ADR 0002](0002-addon-core-compatibility-gating.md)), so an add-on that lists
  `smtp-relay` under `networks.attach` declares `requires.addon_api: 3`, and an older core
  reports it incompatible instead of failing on an unknown service.
- `papaia-ctl doctor` gets an `smtp` check: `not configured`, `reachable`, or
  `unreachable (<stage>: <reason>)`, plus a warning for a stopped relay and a
  non-empty queue. The probe performs the handshake and the login but sends no mail. It
  never fails the run, and it does not contact the upstream from inside a container,
  because `papaia-manager` runs `doctor` there on a timer.

How the image behaves was checked rather than assumed, and three results shaped the
compose file:

- **The generated configuration is on a `tmpfs`.** The image writes the password it reads
  from the file into `/etc/postfix/sasl_passwd` and declares that path as a volume. On a
  volume that survives a recreated container, a changed password is appended next to the
  old one, Postfix keeps the first, and mail queues under "SASL authentication failed". A
  `tmpfs` starts clean, which also keeps the password off disk.
- **The healthcheck is the module's own.** The image's check sends an EHLO to port 587 on
  every run, which fills the log with connect lines and is too strict on slow hosts. The
  module asks the kernel whether port 587 has a listener, which is only true while the
  Postfix master runs. It makes no connection and does not involve the upstream, so a
  provider outage does not turn the relay unhealthy.
- **The relay is hardened as far as the image allows.** It runs with
  `no-new-privileges` and `cap_drop: [ALL]` plus the seven capabilities it needs. It cannot
  use a read-only root file system, because the image changes the mode of its own scripts
  at start.

## Consequences

- **Positive**: the credentials exist in one place, outside the realm JSON, the root
  `.env` and the add-on snapshots, and rotating them is one setup run. Mail survives an
  upstream outage: it waits in a queue on a named volume that backup and restore cover, is
  retried every five minutes at first and with growing intervals up to about an hour, and
  is returned to the sender after a day. Keycloak, the manager and add-ons need no
  credentials and no outbound access of their own. The profile does not depend on Keycloak,
  so it also serves an installation with an external identity provider.
- **Negative**: the Postfix master runs as root inside the container. A send that reports
  success in Keycloak or the manager has been handed to the relay, not delivered; only
  `doctor`, `postqueue` and the relay log show a failing upstream. Any container on a
  network the relay is attached to can send mail as the sender domain without logging in.
  There is one sender domain, and a provider that only accepts verified or mailbox-bound
  addresses needs a matching sender address. The relay rejects recipients whose domain does
  not resolve, so the `.lan` addresses of the seeded accounts cannot receive mail. There is
  no mode for an upstream with a private CA yet. The image also listens on port 25 inside
  the container, under the same client and sender restrictions.
- **Neutral**: the password is in the configuration backup in plain text, like the other
  secrets. Restoring the queue volume can deliver old mail again. Add-ons, the manager's
  own notifications and alerting are separate changes that build on the attachable service.

## Alternatives considered

- **Mail settings in the root `.env`, read by every service** — the costs listed under
  Context: duplicated credentials, a plain-text password in the realm JSON and in the
  add-on snapshots, no queue.
- **`devture/exim-relay`** — small, non-root and actively maintained, but its configuration
  neither requires STARTTLS towards the upstream nor verifies the certificate, so a login
  could go out unencrypted, and its sender verification refuses non-resolvable sender
  domains such as `.lan` unless disabled. It remains the candidate if a non-root relay
  becomes a requirement.
- **A small forwarder built around `decke/smtprelay`** — forwards synchronously, so a mail
  is lost for the sender when the upstream is down; it has no queue or retry, ships no
  container image, and takes its credentials inside a URL.
- **KumoMTA** — built for high-volume senders and configured with Lua policy scripts;
  more than a relay for transactional mail needs.
- **Mailpit as the relay** — a test tool. In relay mode it keeps a copy of every message,
  reset links included, and exposes them in a web interface. It is used as the upstream in
  the tests only.

## References

- [ADR 0002](0002-addon-core-compatibility-gating.md) — the add-on contract generation.
- [ADR 0004](0004-rag-system-as-optional-core-profile.md) — the pattern of an optional core
  profile with realm wiring and a sync for existing realms.
- [`src/infra/smtp-relay/`](../../src/infra/smtp-relay/) and
  [`tools/lib/smtp.py`](../../tools/lib/smtp.py).
