---
adr: 0027
title: Join the network an add-on offers through an exposes entry instead of its app network
status: Proposed
date: 2026-11-23
deciders:
  - WilhelmSebastian
tags:
  - addons
  - network
  - security
supersedes: null
superseded_by: null
---

# 0027. Join the network an add-on offers through an exposes entry instead of its app network

## Context

`networks.join_addons` (contract generation 4) lets listed services of an add-on join the
`app_network` of an add-on it requires, and nothing else (`tools/lib/gen_override.py`).
The app network of an add-on carries its whole API, its ingress and its other services.

A module that offers part of its API to other modules does so through a relay on a
separate named network: papaia Flow offers its `flow.runs` interface at the relay
`flow-module-relay:8080` on the internal network
`${PAPAIA_PROJECT:-papaia}-papaia-flow-modules` and refuses consumers on its app network.
A consumer that joins the app network gets far more than the offered interface; a consumer
that joins nothing cannot reach the offer. Neither is acceptable.

## Decision

Contract generation 17 adds the optional key `network` to a `networks.join_addons` entry:

```yaml
requires:
  addon_api: [17]
  addons:
    - {name: papaia-flow, optional: true}
networks:
  join_addons:
    - addon: papaia-flow
      services: [assist-gate]
      network: ${PAPAIA_PROJECT:-papaia}-papaia-flow-modules
```

1. **Exactly that network.** With `network`, the listed services join that network and
   never the target's `app_network`. The override is written per target to
   `overrides/addons/docker-compose.<name>-offer-<target>.override.yml`; every other
   service of the consumer stays off it. Without the key, the entry renders as before: the
   `-join` override is byte-identical to generation 16.
2. **What counts as offered.** The kit's `exposes` v1 address (`service`, `port`, `scheme`,
   `path`) has no network field, so the core derives the offer from the target's compose
   file: a network is offered when the target's `docker-compose.yml` declares it with a
   `name` and `internal: true` (not `external`), the `address.service` of one of the
   target's `exposes` entries joins it, and it is not the target's `app_network`, its
   egress network or one of its isolated networks. The name follows the template rule of
   `app_network` for the target: `${PAPAIA_PROJECT:-papaia}-<target>-...` or its literal
   default.
3. **Refusals.** The compatibility check (`addon check`, `install`, `start`, `upgrade`,
   `rollback`, `doctor addon_compat`) refuses, naming the entry
   (`networks.join_addons[<i>]`), an entry with an unknown field; a network that is empty,
   not scoped to the target, a core network or one of Docker's networks; a network the
   target's compose file does not create, or creates without `internal: true`; a network
   no `exposes` entry of the target has its address on; the target's app, egress or
   isolated network; and a second entry that joins the `app_network` of a target the
   manifest already joins through its offered network. These are malformed manifests, so `--force` and warn mode do not let
   them through. The render checks the offer again and drops an entry the target no longer
   offers, with a warning: the services then join nothing, never more.
4. **Older cores refuse; forcing them is unsafe.** A core before generation 17 does not know
   the key. It would read the entry as a join of the `app_network`, the very widening this
   generation exists to prevent. Two rules close that path: `networks.join_addons.network`
   is in `GENERATION_FEATURES` with 17, so a core whose window ends below 17 reports the
   add-on `INCOMPATIBLE`, names the missing generation and the entry; and a manifest that
   uses the key must name only generations from 17 on in `requires.addon_api`, so the
   gate of every older core (which has no generation feature for the key) finds no served
   generation and refuses the add-on. This refusal is `INCOMPATIBLE`, which an older core
   lets through with `--force` or in warn mode; there the entry would become a join of
   the target's `app_network`. The current core cannot close that path, so operators must
   never force a manifest that uses the key on a core older than 17.
5. **Absent target.** When the target is optional and not installed or not active, the
   entry is skipped with a warning naming the target and the network; no override names
   the network and the consumer starts. When the target is active but its network does
   not exist when the consumer starts (the target is stopped), `addon start` leaves the
   offer override out with the same kind of warning instead of failing, and
   `doctor addon_compat` reports the missing network.

## Consequences

- **Positive**: a consumer reaches exactly the interface a module offers to modules, and the
  module's app network stays closed to it.
- **Positive**: existing add-ons are unaffected; the key is additive and `min` stays 1.
- **Negative**: the offer is derived from the target's compose file and its `exposes`
  entries, not stated in one field. A target that moves its relay to another network
  changes what it offers; the render then drops the consumer's join until both agree.
- **Neutral**: the services of the consumer on the offered network see every container the
  target puts there. A target offers a network only with the services it wants to offer
  on it.

## Alternatives considered

- **Join the target's app network.** Rejected: the consumer gets every route of the
  target's API and its other services. papaia Flow refuses consumers there.
- **A network field in the kit's exposes address.** Rejected for now: it changes the kit
  schema and every module that validates against it. The core can derive the offer from
  what the target already declares.
- **Let an older core fall back to the app network.** Rejected: an older core would widen
  the join silently. Refusing makes the operator upgrade the core first.

## References

- [ADR 0002](0002-addon-core-compatibility-gating.md) — contract generations and the gate
- [ADR 0026](0026-isolated-add-on-networks-that-reach-only-the-model-gateway.md) —
  isolated networks, the same template rule for network names
- [docs/offered-networks.md](../offered-networks.md) — the add-on author's guide
- [docs/architecture.md](../architecture.md) — the manifest reference and Seam 1
