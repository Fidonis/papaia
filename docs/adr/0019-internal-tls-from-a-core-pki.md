---
adr: 0019
title: Issue internal TLS certificates from one core CA in an optional pki profile
status: Proposed
date: 2026-11-20
deciders:
  - WilhelmSebastian
tags:
  - security
  - tls
  - addons
  - papaia-ctl
supersedes: null
superseded_by: null
---

# 0019. Issue internal TLS certificates from one core CA in an optional pki profile

## Context

Traffic between the services of an installation (an application and its database, a
gateway and its workers, LibreChat and an MCP server) runs over Docker networks in plain
TCP. TLS ends at the reverse proxy. Operators of critical infrastructure (KRITIS, NIS2)
are expected to encrypt and mutually authenticate internal links too, and modules are
starting to depend on it: papaia-studio refuses to start in its KRITIS mode without
internal TLS, and flow, assist and data are expected to follow.

Each module could bring its own CA. Then every add-on has its own trust anchor, its own
key storage, its own renewal and its own failure modes; a service that talks to two
modules needs two bundles, and an audit finds as many CAs as add-ons. Companies that run
their own PKI want internal certificates to chain to it. And the edge certificates
(Let's Encrypt in the Nginx Proxy Manager, a company certificate on an external proxy, a
Cloudflare origin certificate) must not be disturbed.

The core already has two CAs with narrow jobs: the local CA that signs Keycloak's
certificate (`<config>/certs/`) and the link CA of distributed installations (ADR 0010),
which authenticates nodes. Neither issues certificates to arbitrary services.

## Decision

**An optional core profile `pki`, off by default.** `papaia-ctl setup --pki|--no-pki` (and a
wizard question, default no) switches it; the choice is sticky. On, it adds `pki` to
`COMPOSE_PROFILES` and writes `PAPAIA_PKI_DIR` (default `<config>/pki`) to the root `.env`,
which add-on compose files can interpolate. Off, neither exists and nothing else changes.

**One CA per installation, its key in a volume no runtime service mounts.** ECDSA P-256,
`CA:TRUE, pathlen:0`, ten years. The key lives in the named volume `<project>_pki-ca`. It
is mounted only by `pki-issuer`, a one-shot container (`alpine/openssl`, no network,
read-only root, capabilities limited to handing files to other users) that papaia-ctl
runs with `docker compose run --rm`. The issuer is outside the core include list, like the
link gateway, so `docker compose up` never starts it and the core's compose output does
not change. The key is deliberately not in the config directory, which papaia-manager
mounts as a whole.

**Requests are declared, not coded.** An add-on adds a `pki:` block to `papaia-app.yaml`:
`services[]` with `name` (a DNS label and the client CN), `uid` (the numeric user that
reads the files), `server.dns[]` and `client: true|false`. A core module puts the same
block into a `pki.yaml` next to its compose file, with the `profile` it belongs to; its
module name is `core`. The key is additive and ignored by cores that do not know it, so
**`ADDON_API` is not raised**: an add-on that needs the PKI checks for `PAPAIA_PKI_DIR` at
start, and the contract format is versioned separately (`papaia.platform-pki/1`).

**A fixed layout, owned by the consumer.**
`<PAPAIA_PKI_DIR>/<module>/<service>/{ca.crt,tls.crt,tls.key,client.crt,client.key,generation}`,
plus `ca-bundle.crt` and `inventory.json` at the top. Service directories are `0500` and
keys `0400`, owned by the requested uid; certificates and the bundle are world-readable.
Files are replaced atomically in the order keys, certificates, bundle, `generation`.

**Idempotent issuing at every lifecycle point, renewal at two thirds.** The issuer runs on
`setup`, `start`, `addon install|start|remove|uninstall` and `papaia-ctl pki renew`. It
issues what is missing, renews a leaf once two thirds of its lifetime (90 days by
default, at most 90) have passed or when its request or issuer changed, removes what is
no longer requested, and reports what changed; papaia-ctl restarts the running services
and add-ons affected. A run with nothing to do writes nothing.

**Rotation in two steps.** `pki rotate-ca` stages a new CA into every bundle, restarts,
then makes it active, issues every leaf again and restarts. The old CA stays in the bundle
until its last leaf has expired.

**Bring your own.** `rotate-ca --cert --key [--chain]` imports an intermediate of the
company PKI (checked: CA, key usage, key match, lifetime, chain to a root);
`PAPAIA_PKI_MODE=external` issues nothing and installs operator-provided leaves after
checking every one of them first.

**Edge TLS stays separate.** The profile does not touch the reverse proxy, its
certificates, the Keycloak CA or the link CA. The two trust domains are documented side by
side in `docs/pki.md`.

**Distributed installations: controller only.** Certificates are issued on the controller.
Add-ons placed on other nodes are skipped with a warning until node bundles can carry them.

**Operations.** `papaia-ctl pki status|renew|rotate-ca|purge`; `doctor`'s `certs` check
includes the inventory (warning under 14 days, failure under 7); the CA volume carries the
project label and is part of every backup.

## Consequences

- **Positive**: one trust anchor and one layout for every module; KRITIS-oriented modules
  can rely on it instead of building their own; rotation and renewal are uniform and
  observable; a company CA plugs in without code changes in the modules.
- **Positive**: no running container, no open port, no change at all while the profile is
  off; the golden output of an installation without it is unchanged.
- **Negative**: a renewal restarts the services concerned (no hot reload in the contract).
  A daily `papaia-ctl pki renew` is needed on hosts that are not restarted for weeks.
- **Negative**: add-ons on non-controller nodes get no certificates yet.
- **Negative**: the issued leaf keys are visible to whoever can read `PAPAIA_PKI_DIR` as
  root, including papaia-manager when the directory is inside the config directory.
  Operators who mind can move `PAPAIA_PKI_DIR` outside it.
- **Neutral**: the Keycloak CA and the link CA remain; folding them into this CA is a
  possible later step.

## Alternatives considered

- **A CA per add-on** — what the add-ons would do on their own. Rejected: many trust
  anchors, duplicated rotation logic, no single place for a company CA.
- **A resident CA service (step-ca, Vault PKI, cert-manager style ACME)** — gives short-lived
  certificates and online renewal. Rejected for now: another long-running service with
  its own database, port and secrets to protect, for an installation that issues a few
  dozen certificates a quarter. The file contract keeps the door open to swap the issuer.
- **A service mesh or sidecar proxies (mTLS terminated next to each container)** — moves
  TLS out of the applications. Rejected: a large footprint for single-host installations,
  and it does not give the applications the client identity they authorize by.
- **Keep the key in the config directory next to the Keycloak CA** — simpler. Rejected:
  papaia-manager mounts the whole config directory.
- **Raise `ADDON_API`** — would make the `pki:` key a contract feature with a version
  gate. Rejected: the key is optional and additive, older cores ignore it, and an add-on
  needs the runtime fact (`PAPAIA_PKI_DIR` present) rather than a contract generation.

## References

- `docs/pki.md` — operator documentation, layout and commands
- `src/infra/pki/` — the issuer
- ADR 0004 / ADR 0007 — optional core profiles
- ADR 0010 — the link CA of distributed installations
