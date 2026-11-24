---
adr: 0022
title: Define one security profile for the whole installation in one place
status: Proposed
date: 2026-11-21
deciders:
  - WilhelmSebastian
tags:
  - security
  - tls
  - papaia-ctl
supersedes: null
superseded_by: null
---

# 0022. Define one security profile for the whole installation in one place

## Context

`PAPAIA_SECURITY_PROFILE` (`standard`, `kritis`) started as a realm setting: `sslRequired`,
https-only hosts and offline-session limits. The platform PKI now depends on it too, and every
module has to behave the same way under the same value. A module with a switch of its own
could run without platform certificates on an installation that the operator set to `kritis`.

## Decision

**One variable, one definition.** The root `.env` carries `PAPAIA_SECURITY_PROFILE`.
`tools/lib/security_profile.py` is the only part of the core that names it; it defines the
two values and a table of what each means. Every other part of papaia-ctl asks that module.
Modules read the same variable from the root `.env` and keep no switch of their own. The
table in [configuration.md](../configuration.md#what-each-security-profile-means) is
checked against the module by a test.

**What the values mean.**

- `standard`: realm `sslRequired: external`; offline sessions (the delegation lifetime)
  by default 90 / 180 days, settable up to 365 days each; TLS
  ends at the proxy; the audit ingest uses mutual TLS with its own CA (docs/audit.md);
  platform certificates ([ADR 0019](0019-issue-internal-tls-from-one-platform-ca.md)) are
  issued for every request.
- `kritis`: realm `sslRequired: all`; every configured host https; offline sessions at most
  7 / 30 days (default and upper bound); an add-on without a `pki:` request is refused at
  `addon install`, and `start` refuses an active one; the proxy and the catalog reach the
  module services (Flow, the assistant, Me, the connection registry) over TLS of the
  platform CA, and a module service without a server certificate for the name it is
  reached under stops the render (`tools/lib/module_tls.py`, docs/pki.md).

The table states only what the core enforces. Apart from the module services, links
between core containers do not use TLS in either profile yet; when a later change wires
them to the platform PKI, it changes the row of the table and the test that holds the
table to the code. The module services are a fixed list rather than every add-on with a
certificate: whether another add-on listens with TLS under `kritis` is not known to the
core, and forwarding to it with https would break it.

Any other value stops the render, the realm sync and the issuing of certificates.

## Consequences

- **Positive**: one place to look up what a profile means; a module cannot drift from the
  installation's choice.
- **Negative**: under `kritis` an add-on must ship a `pki:` request (contract generation
  11) before it can be installed.
- **Neutral**: `standard` stays the default; its behaviour does not change.

## Alternatives considered

- **A switch per module** — the operator would have to set it in every module and could
  miss one.
- **A separate variable for internal TLS** — two variables that can contradict each other.

## References

- `tools/lib/security_profile.py`
- `tools/lib/module_tls.py` — TLS to the module services under `kritis`
- [ADR 0019](0019-issue-internal-tls-from-one-platform-ca.md) — the platform PKI
