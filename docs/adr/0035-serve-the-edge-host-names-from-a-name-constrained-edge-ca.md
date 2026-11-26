---
adr: 0035
title: Serve the edge host names with certificates of a name-constrained edge CA
status: Proposed
date: 2026-11-26
deciders:
  - WilhelmSebastian
tags:
  - security
  - tls
  - papaia-ctl
supersedes: null
superseded_by: null
---

# 0035. Serve the edge host names with certificates of a name-constrained edge CA

## Context

Behind the bundled Nginx Proxy Manager every interface has an https host name
(`https://auth.<domain>`, locally `https://auth.<env>.papaia.localhost:<edge port>`).
`npm-provision` created each proxy host without a certificate, and the answer `internal`
to row 3 of the question round issued nothing for the edge. On a fresh installation every
https request to a host name at the edge therefore ended in TLS alert 112
(`unrecognized_name`): sign-in, token requests and the issuer discovery from the host
failed, and an operator had to set up a certificate in the proxy's admin UI by hand.

Operation asks that the internal CA issues a certificate per host name (BE-04) and that a
new installation needs no step in an admin UI (PLT-32-A1); with `internal` the operator
only distributes the root certificate.

[ADR 0019](0019-issue-internal-tls-from-one-platform-ca.md) keeps edge TLS out of the
platform CA on purpose. A root that every browser and host of the operator trusts must not
be able to sign anything else: not the identities of internal services (the platform
CA's job) and not a name outside the installation. The Keycloak CA is limited to
Keycloak's own names and is trusted separately (macOS keychain step of `setup`).

## Decision

**A dedicated edge CA per installation, contract `papaia.edge-pki/1`.** With the bundled
proxy (`internal_nginx`) and `tls: internal` (row 3, or a setup with switches, which has
no bundle), papaia-ctl keeps an edge CA in the configuration directory: ECDSA P-256, ten
years, `CA:TRUE, pathlen:0`, key usage certificate and CRL signing only. papaia-ctl issues
with the host's openssl, as for the other CAs.

**Where the files are.** `certs/` is mounted read-only into many services (Keycloak's
CA, the trust bundle), so it holds only the public root, `certs/edge-ca.crt`, which the
operator distributes. The CA key (`pki/edge/ca.key`, 0600), its domains (`ca.json`), the
lock and every leaf live in `pki/edge/` (0700), as the platform CA's key lives in
`pki/ca/`: no service's compose file mounts it, and a test over every compose file of
the repository keeps it so. The one exception is the manager, which runs papaia-ctl
itself with the Docker socket and the whole configuration directory: it acts as the host
account and could read the platform CA key the same way. `edge` is a reserved module name
of the platform PKI, which leaves the directory alone.

**Name constraints.** The CA carries critical name constraints that permit exactly the
installation's base domain and app domain (from the host scheme: `INGRESS_DOMAIN` or the
domain of `PAPAIA_HOST`, and `INGRESS_APP_DOMAIN`; locally the two registrable domains
below `localhost` that setup derives, `<env>.papaia.localhost` and
`<env>.papaia-apps.localhost`). An app domain inside the base domain (one site, E-20) is
covered by it. Addresses are excluded. A client that checks name constraints (every
current browser and OpenSSL) refuses a certificate of this CA for any other name, even
one signed with its key by hand. If the domains change, the CA is replaced and every leaf
is issued again; the operator distributes the new root.

**Leaves.** One leaf per proxy host papaia-ctl creates and owns: the core's interfaces,
the add-ons' interfaces, the Paperless route and the main address. A leaf carries
`serverAuth` only, `CA:FALSE`, and as subject alternative names exactly the names of its
proxy host (one name; the app host has its domain and the wildcard below it). Clients
match the subject alternative names only; the subject's common name is the first name
when it fits the 64 characters X.509 allows and is left out otherwise, and the CA's
common name is `papaia-edge-ca <base domain>`, or `papaia-edge-ca <hash of the domains>`
for a base domain too long for it, so a long name never stops `start`. It lives
90 days in `pki/edge/leaves/<first name>/{tls.crt, tls.key, request.json}` (directory
0700, key 0600). A leaf key reaches the proxy only through its API (below). papaia-ctl refuses a name outside the CA's domains (an operator-set address of
another domain): it issues nothing for it, names it in a warning, and the host keeps what
it has.

**When.** `setup`, `start`, `addon start` and `certs renew` run the issuer (`pki-issue`,
after the platform PKI): it issues what is missing, renews a leaf with 30 days or less
left or whose names or CA changed, and removes the leaf of a host no longer served. One
run writes at a time (lock `pki/edge/.lock`). Every new CA, issue, renewal and removal
is one `papaia.audit/1` row (writer `papaia-ctl/edge-pki`, result `allowed`, or `error`
when the write failed and the run stops); a run with nothing to do writes nothing.

**At the proxy.** `npm-provision` (part of `start` and `addon start`) uploads each leaf as
a custom certificate through the proxy's API and sets it on the hosts papaia-ctl creates.
A renewed leaf is uploaded anew, set on its host, and the earlier upload deleted. The
upload of a removed leaf is deleted once no host uses it any more (its host is removed
with its add-on or the entry page). The ids papaia-ctl uploaded are kept in
`pki/edge/npm-certificates.json`; only those are ever replaced or deleted. Should that
file be lost, the custom certificates named `papaia edge <name>` for a name of the CA's
domains are taken as earlier uploads: replaced on their hosts and deleted once unused, so
no host keeps an upload whose leaf runs out. Every upload
and deletion is one `papaia.audit/1` row (writer `papaia-ctl/npm-provision`) without key
material: an upload that fails is an `error` row (`file` when the leaf cannot be read and
nothing is sent, `transport` when the proxy refuses the entry or its files), and the entry
it leaves without files is deleted again with a `delete_certificate` row of its own. A run with nothing changed makes no write to the proxy.

**What stays.** A certificate the operator set on a host stays: papaia-ctl only sets a
certificate on a host without one or with one it uploaded itself, and a host for which no
leaf applies (a refused name, a failed upload) keeps whatever certificate it has. Forcing
https and HSTS are not changed. With a PEM bundle as answer to row 3 nothing of this runs.

**Trust.** `setup` prints where the root certificate is; on macOS it offers to trust the
edge CA in the login keychain for TLS server certificates only, or prints the
`security add-trusted-cert` command, as for the Keycloak CA. `doctor certs` checks the
edge CA and its leaves with the existing thresholds; `certs status` lists them. Backup
and restore carry `certs/` and `pki/` with the configuration directory, so a restore on
the same names keeps the trust.

## Consequences

- **Positive**: a fresh installation serves every host name it creates over https without
  a step in the proxy's admin UI; clients that trust `certs/edge-ca.crt` reach the issuer
  at its public address.
- **Positive**: the root the operator distributes cannot vouch for any other name, and it
  is not the root of the internal service identities.
- **Negative**: the leaf keys are in the proxy's data volume, as the key of any
  certificate the proxy serves.
- **Negative**: a renewed leaf reaches the proxy at the next `npm-provision` (part of
  `start`); a host that is not restarted for two months needs a daily `certs renew`
  followed by `npm-provision`.
- **Negative**: whoever can read the configuration directory as its owner or root (the
  host account, and the manager, which acts as it) can read the CA key; the same boundary
  as for the platform CA. No other container sees it.
- **Neutral**: on a distributed installation the leaves are issued on the controller;
  `npm-provision` runs where the proxy runs and uploads the leaves it finds there.

## Alternatives considered

- **Issue the edge leaves from the platform CA** — every browser would trust an
  unconstrained CA that also signs internal service identities; against ADR 0019.
- **Extend the Keycloak CA's name constraints** — constraints are part of the CA
  certificate, so this needs a new CA anyway, and it mixes the existing trust step with a
  new one.
- **Keep the manual step in the proxy's admin UI** — contradicts BE-04 and PLT-32-A1.

## References

- [ADR 0019](0019-issue-internal-tls-from-one-platform-ca.md) — the platform CA
- `tools/lib/edge_pki.py`, `tools/lib/npm_provision.py`, `tools/lib/sh/certs.sh`
- [docs/pki.md](../pki.md) — operator documentation of the CAs
