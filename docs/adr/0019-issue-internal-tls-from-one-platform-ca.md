---
adr: 0019
title: Issue the certificates for internal TLS from one platform CA
status: Proposed
date: 2026-11-21
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

# 0019. Issue the certificates for internal TLS from one platform CA

## Context

Behind the reverse proxy, services talk to each other over Docker networks in plain TCP.
Operators of critical infrastructure expect internal links to be encrypted and mutually
authenticated, and the modules (studio, flow, assist, data, me) are built to read
certificates from the platform instead of running a CA each. papaia-lifecycle and the
`/internal/*` endpoints of modules are meant to use mutual TLS; for that they first need
certificates from one issuer ([ADR 0022](0022-one-security-profile-for-the-whole-installation.md)).

The core already has three CAs with narrow jobs: the local CA that signs Keycloak's
certificate, the link CA of distributed installations (ADR 0010) and the ingest CA of the
audit store, whose client certificates are pinned per audit source (docs/audit.md). None issues
certificates to arbitrary services. Companies with their own PKI need their root
certificates trusted by every container, in one place.

## Decision

**One platform CA per installation, contract `papaia.platform-pki/1`.** ECDSA P-256,
`CA:TRUE, pathlen:0`, ten years. Its key is `<config>/pki/ca/ca.key` (directory 0700,
key 0600); no container mounts it. papaia-ctl issues with the host's openssl, like the
two CAs before it; there is no resident CA service.

**Requests are declared.** An add-on lists the certificates it needs in the `pki:` key of
`papaia-app.yaml` (contract generation 11): `services[]` with `name` (a DNS label, the
client certificate's CN), `uid` (the numeric user that reads the files, optional),
`server.dns[]` and `client`. Unknown keys are refused. A core module puts the same block
into `pki.yaml` next to its compose file, with the `profile` it belongs to; its module
directory is `core` unless the file names another `module`.

**A fixed layout.** `<config>/pki/<module>/<service>/{ca.crt, tls.crt, tls.key,
client.crt, client.key, generation, request.json}`, plus `ca-bundle.crt` and
`inventory.json`. Service directories are 0700 and keys 0600, handed to the requested
`uid` when papaia-ctl runs as root. Keys are replaced before certificates, `generation`
is written last; a consumer that sees a new `generation` sees a complete set.
`PAPAIA_PKI_DIR` names the directory for consumers.

**Idempotent issuing at every start, renewal at two thirds.** Leaves live 90 days. `setup`,
`start`, `addon start` and `papaia-ctl certs renew` issue what is missing, renew a leaf
with 30 days or less left or whose request or CA changed, and remove what is no longer
requested. `certs renew --ca` replaces the CA; the old one stays in every bundle for 90
days, until the last leaf it signed has ended. A new CA is made as temporaries and moved
into place key first; a key that does not match its certificate is replaced at the next
run. One run writes at a time (exclusive lock on `<config>/pki/.lock`). Every issue, renewal, removal, new CA and
import is one `papaia.audit/1` row; a run with nothing to do writes nothing.

**One place for trust anchors.** `<config>/certs/trust/ca-bundle.pem` holds the platform CA
and the company roots imported with `setup --ca-bundle=FILE` (or the setup question). The
file is checked at once: only CA certificates (CA:TRUE in the Basic Constraints
extension itself), none expired, no private key. An unusable
answer is asked for once more, then setup stops.

**Edge TLS and the audit ingest stay separate.** The reverse proxy's certificates, the
Keycloak CA, the link CA and the ingest CA of the audit store are not touched. The audit
ingest keeps its own CA because a source is pinned by the fingerprint of its one client
certificate; a platform certificate must not be able to deliver events.

**Doctor.** `doctor certs` checks the platform CA, every service certificate and the trust
bundle with the existing thresholds (warning under 30 days, failure under 7 or expired).

## Consequences

- **Positive**: one trust anchor and one layout for every module; renewal and rotation
  are uniform and audited; a company root is trusted without code in the modules.
- **Positive**: no running container and no open port for the PKI.
- **Negative**: a service that does not watch `generation` reads renewed files at its next
  start; `start` renews, so a host that is not restarted for two months needs a daily
  `papaia-ctl certs renew`.
- **Negative**: whoever can read the configuration directory as root can read the CA key;
  that is the same boundary as for the Keycloak CA and the link CA.
- **Negative**: this decision issues certificates; it does not switch a core link to TLS.
  papaia-lifecycle gets its files but does not mount or present them, and no core
  service mounts the trust bundle (Keycloak's truststore, the mail sender). Both are later
  steps; until then a company root does not reach the core services.
- **Neutral**: add-ons placed on other nodes of a distributed installation get their files
  on the controller only; carrying them in node bundles is a later step.

## Alternatives considered

- **A CA per module** — many trust anchors, duplicated rotation logic, no single place for
  a company CA.
- **A resident CA service with online enrollment** — short-lived certificates, but another
  long-running service with its own port, database and secrets, for a few dozen
  certificates a quarter. The file contract leaves room to swap the issuer.
- **A service mesh with sidecar proxies** — a large footprint for single-host installations
  and no client identity inside the application.

## References

- [docs/pki.md](../pki.md) — operator documentation
- `tools/lib/pki.py`, `src/infra/*/pki.yaml`
- ADR 0002 — contract generations; ADR 0010 — the link CA
- [ADR 0022](0022-one-security-profile-for-the-whole-installation.md) — the security profile
