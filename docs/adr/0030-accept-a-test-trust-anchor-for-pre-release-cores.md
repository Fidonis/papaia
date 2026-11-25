---
adr: 0030
title: Accept a test trust anchor for pre-release cores
status: Accepted
date: 2026-11-25
deciders:
  - WilhelmSebastian
tags:
  - release
  - security
  - supply-chain
supersedes: null
superseded_by: null
---

# 0030. Accept a test trust anchor for pre-release cores

## Context

Before `start` and `upgrade` run an image, and before `pairing confirm` records an exchange
right, the core checks the signed suite bill of materials of its version
(`compat/suite-<version>.yaml`, lib/suite.py). The only anchor is the release key pinned in
the checkout, `compat/release-key.pub`, and the file must have the scope `delivery`; image
signatures are then checked against the key of that file (lib/images.py).

The release key signs deliveries only. A release candidate is built and signed before the
release, with a local test key, and described by a bill of materials of scope `test`. Such a
file cannot be used for `start`, `upgrade` or `pairing confirm`, so no candidate can be
tested end to end against the very checks that guard a delivery. Skipping the checks
(`--insecure-images`) tests nothing of them and does not cover `pairing confirm`.

## Decision

A pre-release core accepts a second, explicit anchor for one command:
`--test-trust-anchor=FILE`, a P-256 public key file as `cosign generate-key-pair` writes it.

- **Commands.** `start`, `upgrade`, `pairing confirm`, `pairing list` (it shows the digest
  `confirm` needs) and `suite verify`. Every other command refuses the option.
- **Pre-release cores only.** The core `VERSION` must be a SemVer version with a
  pre-release part and no build metadata (`1.10.0-rc.1`). It is read first; on a release
  version, or on any doubt about it (missing, unreadable, malformed), the command is refused
  before the key, the bill of materials, the image list or anything else is read. In an
  `upgrade` the installed core checks its version when the command starts, and the target
  checks its own before its bill of materials is read, so both must be pre-releases.
- **Scope `test`, exactly that key.** The bill of materials of the core's suite must have
  the scope `test`, the suite of the core version, an embedded key that hashes to the
  fingerprint of FILE, and a signature that holds with it. Image signatures are checked
  against that key, as they are against the release key of a delivery.
- **The release path does not change.** Without the option, nothing differs: the pinned
  `compat/release-key.pub` stays the only anchor, a `delivery` bill of materials needs it, a
  `test` bill of materials is refused. With the option, a `delivery` bill of materials is
  refused, and the pinned key is neither read nor changed. The option combines with neither
  `--insecure-images` nor an upgrade's release-key anchor.
- **Never implicit.** Only the command line sets it. No environment variable, configuration
  file or stored state turns it on; `papaia-ctl` takes the option out before the command
  runs and resets its variable when its libraries load. Nothing of it is written except the
  audit rows; the next command is strict again.
- **Visible.** A banner on standard error opens and closes the command (key fingerprint,
  scope `test`, "NOT FOR PRODUCTION", correlation id, exit code at the end). Every check of a
  bill of materials with the anchor writes one `papaia.audit/1` row, event
  `test_trust_anchor_used`, to `$PAPAIA_CONFIG_DIR/audit/papaia-ctl.jsonl`: the command, the
  key fingerprint, the digest of the bill of materials, the core version, the host login of
  the operator and the correlation id, with result `allowed`, or `denied` when the file does
  not verify. No key material and no content of the file is written.

## Consequences

- **Positive**: candidates are tested through the same digest, signature, scope and pairing
  checks as a delivery. A test key can never vouch for a release core or for a `delivery`
  file, and every use is on record.
- **Negative**: a second anchor exists in code. Its reach is bounded by the version gate:
  whoever controls a pre-release checkout could also change its code, so the gate adds no
  trust a release core does not already have.
- **Neutral**: an `upgrade` with the option writes a row for the target check and one when
  its second phase starts the stack, under one correlation id, as `--insecure-images` does.

## Alternatives considered

- **Sign candidates with the release key.** Rejected: the release key would sign files that
  are never delivered, and a candidate file would differ from a delivery in scope only.
- **A switch in the configuration or an environment variable.** Rejected: it would outlive
  the command and could stay on in production.
- **Skip the checks with `--insecure-images`.** Rejected: it tests none of the checks and
  does not reach `pairing confirm`.

## References

- ADR 0002 (contract generations), lib/suite.py, lib/images.py, lib/prerelease_anchor.py
- README, "Image pinning and signatures"
