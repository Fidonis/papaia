---
adr: 0009
title: Describe a distributed installation with a topology block and place it per service
status: Proposed
date: 2026-10-30
deciders:
  - fwahl711
tags:
  - topology
  - papaia-ctl
  - deployment
supersedes: null
superseded_by: null
---

# 0009. Describe a distributed installation with a topology block and place it per service

## Context

An installation has always been one host: one config tree, one Docker daemon, one Compose
project, one network (`papaia-net`). Some operators have to put ingress, identity and the LLM
gateway on a machine at the network edge (a DMZ) and the application and its data behind it.

Before any of that can run, the installation needs a model of it: which service runs on which
machine, and how the one configuration tree turns into what each machine needs. That model has
to leave every existing single-host installation exactly as it is.

## Decision

- **A `topology` block in `deployment.yaml` describes the installation.** It holds `mode`
  (`single` or `distributed`), the `controller` node, the `nodes` (address, executor `local`
  or `ssh`, SSH user and port, the node's directory), the `placement` of services on nodes and
  the `link` port. A missing block means `single`. `setup` and `upgrade` never write the block
  into an existing `deployment.yaml`. A distributed `setup` of a new installation writes it once.
- **The unit of placement is a service of a fixed catalogue**, not a container and not a
  profile. A service is one or two Compose profiles plus everything they always bring along:
  Nginx Proxy Manager (with its auth sidecar and oauth2-proxy), Keycloak, LiteLLM, LibreChat,
  LibreChat web search, LocalAI, the RAG system, the SMTP relay and papaia-manager.
  Dependencies inside a profile are hard, and every `depends_on` that crosses a profile is
  optional (enforced by `tests/test_compose_profiles.py`). So a profile can always live on
  another node than its optional peers.
- **Services not named in `placement` stay on the controller.** The controller is the machine
  that runs `papaia-ctl` and holds the configuration tree, the CA keys and the SSH keys.
  papaia-manager and the RAG system must run there: they work on the configuration directory
  itself. Web search must run with LibreChat. LocalAI is checked against the node's hardware
  hint.
- **Two profile levels.** On each node `COMPOSE_PROFILES` names what starts there.
  `PAPAIA_ACTIVE_MODULES` names the profiles of the whole installation. Whatever is decided once
  for all nodes reads the second: the realm clients the Keycloak sync creates, the proxy hosts
  the Nginx Proxy Manager gets, whether the mail relay exists. A single-node `.env` never
  carries the second key, and the readers fall back to `COMPOSE_PROFILES`.
- **Every render in distributed mode projects one bundle per node** into
  `$PAPAIA_CONFIG_DIR/nodes/<name>/bundle/`. A bundle holds the node's root `.env`, plus the
  `.env` files, rendered configuration and certificates of the services placed there, and the
  core overrides. Secrets of services on other nodes are left out, including the ones in the
  root `.env`: they are blanked unless a Compose file of one of the node's own services
  references them. The local CA key and the SSH keys never enter a bundle. State a service
  keeps on its own node (the proxy's database and certificates) is never shipped.
- **Two presets** cover the expected uses: `dmz-split` puts Nginx Proxy Manager, Keycloak,
  the SMTP relay and LiteLLM at the edge, and `dmz-edge` only Nginx Proxy Manager and LiteLLM.
- **Golden tests pin the single-node output first.** Before any of this landed, the rendered
  tree, `docker compose config`, `deployment.yaml` after a repeated `setup` and after an
  upgrade, `status --json`, `doctor --json`, the backup manifest and the setup defaults were
  pinned for three fixture deployments. They stay green through every later change.

## Consequences

- **Positive**: Existing installations see no change: no new key in any file they have, no new
  question in `setup`, the same JSON from `status` and `doctor`.
- **Positive**: Placement is validated before anything changes, with a message that names the
  service, the node and the reason.
- **Positive**: A node only ever holds the secrets of what runs on it. An edge node that is
  compromised does not hand over the database passwords of the internal one.
- **Negative**: The catalogue is a list in code. A new optional module needs an entry. The
  catalogue tests fail when a profile or an env directory belongs to no service.
- **Negative**: In distributed mode every public URL has to be a host name without a port,
  because the bundled proxy serves all of them from its node.
- **Neutral**: The controller's bundle points at the full configuration tree, since
  papaia-manager mounts it. Only the env files differ from the single-node layout.

## Alternatives considered

- **Named groups of services ("edge", "identity") on top of services** — one more concept for
  no gain. The presets cover the use.
- **Placement per container** — breaks the hard dependencies inside a profile. A Keycloak
  without its database on the same node cannot start.
- **Placement per profile** — `oauth2-proxy` and `nginx` are separate profiles but only work
  together. The catalogue keeps such pairs one unit.
- **One Compose project spanning several daemons** — Compose has no such thing. Swarm would,
  at the cost of Swarm membership at the edge and bidirectional cluster ports.

## References

- `tools/lib/topology.py` — catalogue, model, validation, presets, projection.
- `tools/tests/test_golden_single_node.py` — the single-node output this must not change.
