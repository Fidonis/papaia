---
adr: 0034
title: Let a second host account approve a pairing as root in the configuration directory of another account
status: Proposed
date: 2026-11-26
deciders:
  - WilhelmSebastian
tags:
  - security
  - pairings
  - audit
supersedes: null
superseded_by: null
---

# 0034. Let a second host account approve a pairing as root in the configuration directory of another account

## Context

A write pairing (effect `w` or `d`) is assigned only after a second host account approves
it (security 1.4, "Pairing approval" in `docs/architecture.md`). The account that confirmed
the list at `setup` owns the configuration directory and `security/pairings.yaml`; the
second account runs `sudo tools/papaia-ctl pairing approve`, and the acting person is the
`SUDO_USER`, believed only at effective uid 0.

That call could not succeed. The file check shared with the realm sync accepts
`pairings.yaml` and `security/` only when they belong to the effective user or to root.
As root that reads "owned by root", so the approval stopped with `... pairings.yaml is owned
by uid 501, not by the user running papaia-ctl` (exit 2). As the second account without
root the file is not its own; the owner cannot be the second person. Had the check passed,
the rewrite would have left a root-owned `pairings.yaml` (and a root-owned lock file and
audit outbox) that the owner's realm sync at `start` could not open.

## Decision

As root, the pairing commands (`pairing list`, `confirm`, `approve`, `revoke`) trust the
owner of the configuration directory, and they write only through directory descriptors:

1. The configuration directory is opened with `O_DIRECTORY | O_NOFOLLOW`. It must not be
   writable by group or others. Its owner (uid and gid) is the owner of everything root
   writes below it.
2. `security/` and `pairings.yaml` are accepted when they belong to root or to that owner
   and group and others cannot write them. A third owner, a group- or other-writable file
   or folder and a symbolic link are refused (exit 2); nothing is written then.
3. Every folder and file is opened relative to its parent descriptor with `O_NOFOLLOW`. The
   new `pairings.yaml` is created next to the old one, handed to the owner (`fchown`) with
   mode `0600` and renamed over it. The lock file, the audit outbox and its counter, and with
   `--test-trust-anchor` the host's audit journal, are opened the same way; a missing file
   or folder is created and handed to the owner. An existing file root appends to must be a
   regular file of the owner with exactly one link.
4. Without root nothing changes. The realm sync, the federation file and the Paperless name
   list keep the rule "owned by the running user or root".
5. The decision rules do not change: a write pairing is confirmed only by another named host
   account than the one that requested it; the same person is refused and audited
   (`same_person`); the realm sync refuses a confirmed write pairing without two different
   accounts. The audit row of the approval names the second account (`host:<SUDO_USER>`).

The limit is documented, not hidden: the account that owns the configuration directory
holds the identity provider's admin credentials (`infra/keycloak/.env`) and may edit
`pairings.yaml` by hand. The second approval is an organisational control with audit
evidence, not a barrier against that account.

## Consequences

- **Positive**: the documented `sudo tools/papaia-ctl pairing approve` of a second account
  works, and the owner's next `start` assigns the pairing.
- **Positive**: a root run leaves no root-owned file or folder in the configuration
  directory and never writes through a link the owner could plant, so root writes nothing
  outside that directory.
- **Neutral**: the second account needs a sudoers rule for exactly this checkout's
  `tools/papaia-ctl`. Such a rule lets that account run every papaia-ctl command as root;
  choose the account accordingly.
- **Negative**: a configuration directory that group or others can write, or that is
  reached through a symbolic link, cannot be used for an approval as root until it is
  fixed (`chmod go-w`, the real path).

## Alternatives considered

- **Record approvals in a separate, root-owned file that the realm sync requires for write
  pairings.** It does not stop the owner of the configuration directory, who can grant the
  scope directly with the identity provider's admin credentials. It needs a store outside
  the configuration directory (in a folder of the owner, an older root-owned file could be
  swapped back), a read-only mount into the admin one-shot container and a backup rule.
  Larger for no gain against that account. Rejected.
- **Let the second account approve without root through a shared group or an ACL.** The
  file then belongs to two accounts, the realm sync's owner rule no longer holds and
  `SUDO_USER` cannot name the person. Rejected.
- **Make the identity provider's admin credentials unreadable for the owner of the
  configuration directory**, so that the second approval also binds that account. A
  separate design question; not part of this decision.
