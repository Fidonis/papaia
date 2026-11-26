---
adr: 0032
title: Place every network of the installation in one operator-given address pool
status: Proposed
date: 2026-11-26
deciders:
  - WilhelmSebastian
tags:
  - network
  - operations
  - security
supersedes: null
superseded_by: null
---

# 0032. Place every network of the installation in one operator-given address pool

## Context

The networks of an installation take whatever range Docker's default address pools hand
out. On a host whose default pools overlap the company network a container cannot reach
the part of the company network its bridge shadows, and the operator cannot say in
advance which ranges the stack will occupy. The only lever so far was the Docker daemon
(`default-address-pools`), which restarts every container on the host, including those of
other projects. Two installations on one host also had no way to keep to the ranges
planned for them.

Only the SQL uplink had a fixed range of its own (`PAPAIA_SQL_UPLINK_SUBNET`).

## Decision

1. **One pool.** `papaia-ctl setup --subnet-pool=CIDR` stores `PAPAIA_SUBNET_POOL` in the
   root `.env` (sticky like the other answers, `--no-subnet-pool` empties it). The pool is
   a private IPv4 range (inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16), validated
   at the boundary. It is cut into blocks of `/PAPAIA_SUBNET_BLOCK` (24 to 28, default 24,
   `--subnet-block=N`) and holds at least 16 of them: /8 to /20 for blocks of /24.
2. **Fixed block order.** The networks of the core's Compose project take the first
   blocks in a fixed list (`CORE_NETWORKS` in `tools/lib/subnet_pool.py`, append only):
   `papaia-net` the first, then the exit, audit, lifecycle, replay, chat relay, Docker
   gate, preference store and connection registry networks. The address of a core network
   depends on the pool alone.
3. **Sticky blocks for the rest.** Every other network gets the lowest free block once
   and keeps it in `$PAPAIA_CONFIG_DIR/subnet-pool.json`: the networks the core's own
   overrides declare (the exits of LiteLLM, papaia-audit and papaia-lifecycle) and the
   networks an active add-on's compose file creates without a range of its own (app,
   egress and isolated networks, ADR 0026; offered networks, ADR 0027). An add-on's
   blocks are freed when it leaves `deployment.yaml`. A network that declares its own
   range keeps it; the SQL uplink keeps its variable, which must not overlap an assigned
   block.
4. **Overrides, not edits.** The blocks reach Compose through generated overrides: one
   for the core project beside the image mirror override, one per add-on in
   `overrides/addons/`. Without the variable none is written and an installation behaves
   as before.
5. **Checks.** `setup` refuses, before anything is written, a pool that is not valid, is
   too small for the networks the installation has, or overlaps a Docker network of the
   host that does not belong to the installation, and names that network. `start`
   repeats the overlap check and refuses a network of the installation that lies outside
   the pool. `doctor network` reports both as `fail` with the fix. A foreign network is
   never removed or changed.
6. **Derived addresses follow.** With a pool the mail relay accepts mail from the pool
   instead of every private range (unless `SMTP_RELAY_ALLOWED_CLIENTS` is set), `NO_PROXY`
   of LiteLLM and papaia-lifecycle names the assigned range of the network they share
   with their direct peers (never their exit network), and an internal egress target
   that overlaps the pool is refused.
7. **A change of the pool** is a documented step: `setup --subnet-pool=NEW` names the
   networks still in the old range; `papaia-ctl stop --clean-up --addons` removes the
   containers and networks (volumes stay), and `papaia-ctl start` creates them in the
   new pool.

## Consequences

- **Positive**: the operator decides which ranges the stack touches without changing the
  Docker daemon; two installations on one host keep to their own ranges; the egress rules
  and the mail relay follow the assigned ranges and none is widened.
- **Negative**: a change of the pool needs a stop with `--clean-up`; a pool too small for
  the installed add-ons stops the render until a larger pool or smaller blocks are set.
- **Neutral**: a distributed installation is refused the option: each node keeps the
  address pools of its own Docker daemon. IPv6 ranges are not placed.

## Alternatives considered

- **`default-address-pools` of the Docker daemon** — restarts every container on the host
  and affects foreign projects; kept in the documentation as an alternative, not as the
  fix.
- **Fixed subnets in the compose files** — two installations on one host would collide.
- **Blocks by hash of the network name** — stable without state, but two names can land
  on one block, and the pool would have to be much larger than the number of networks.

## References

- `tools/lib/subnet_pool.py`, `docs/network.md` (Address range of the networks)
- ADR 0026, ADR 0027
