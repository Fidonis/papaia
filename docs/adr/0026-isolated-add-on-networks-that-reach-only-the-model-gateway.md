---
adr: 0026
title: Let an add-on declare isolated networks that the core joins with the model gateway only
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

# 0026. Let an add-on declare isolated networks that the core joins with the model gateway only

## Context

A module that hands foreign content (a mail, a document, a web page) to a model has to run
that step in a process whose only peer is the model gateway LiteLLM: if an instruction
hidden in the content takes over the process, it must find nothing to talk to except the
model. The process holds no client secret, no delegation and no route to the proxy, the
identity provider, the tool servers or a database.

Up to contract generation 15 an add-on has exactly one network the core joins:
`networks.app_network`, with the core services listed under `networks.attach`
(`tools/lib/gen_override.py`). If LiteLLM is attached there, a service of the add-on that
needs LiteLLM shares that network with every other service of the add-on and with every
attached core service (proxy, identity provider, audit store, mail relay). The rule above
cannot be met by an add-on.

## Decision

Contract generation 16 adds the manifest key `networks.isolated`, a list of up to eight
entries next to `app_network`:

```yaml
networks:
  app_network: ${PAPAIA_PROJECT:-papaia}-<name>-net
  attach: [nginx-proxy-manager, keycloak, papaia-audit]
  isolated:
    - network: ${PAPAIA_PROJECT:-papaia}-<name>-reader-net
      attach: [litellm]
```

1. **One allow-list, closed.** `attach` of an isolated network may name only services of
   `ISOLATED_ATTACHABLE` in `tools/lib/compat.py`, which holds `litellm` and nothing else.
   No service of `NEVER_ATTACHABLE` is in it. The contract snapshot
   (`tools/tests/test_contract_surface.py`) pins the set.
2. **Exactly the listed services.** The override generation puts each listed service on the
   isolated network, next to the networks it already has, and nothing else: the add-on's
   ingress proxy, its egress attachment, the front network of a header-identity add-on and
   every other automatic attachment stay on `app_network` or their own networks. Without
   the key the generated override is byte-identical to generation 15.
3. **`internal: true` is mandatory.** The add-on's own `docker-compose.yml` must create the
   network, under the declared name, with `internal: true` and not as `external`. Docker
   gives an internal network no gateway to the host's routes, so a service on it reaches
   neither the internet nor the host's LAN. Without this, an isolated network would be an
   ordinary bridge with a way out, and "only LiteLLM" would not hold.
4. **Refusals.** The compatibility check (`addon check`, `install`, `start`, `upgrade`,
   `rollback`) and the render refuse, naming the entry (`networks.isolated[<i>]`), an entry
   with an unknown field; an empty, duplicate or non-allow-listed `attach`; a network name
   not scoped like `app_network` (`${PAPAIA_PROJECT:-papaia}-<name>-...` or its literal
   default); a network equal to the add-on's `app_network`, its egress network, another
   entry, a core network or one of Docker's networks; a network the add-on's compose file
   does not create with `internal: true`. The render also refuses a network another add-on
   in `deployment.yaml` declares. These are malformed manifests, so `--force` and warn mode
   do not let them through.
5. **Generation gate.** `networks.isolated` is in `GENERATION_FEATURES` with 16: a core whose
   window ends below 16 reports the add-on `INCOMPATIBLE` and names the missing generation
   instead of starting it with LiteLLM absent from the network.

## Consequences

- **Positive**: an add-on can run a service whose only peer is LiteLLM, and every manifest
  that would widen that isolation is refused before anything changes.
- **Positive**: existing add-ons are unaffected; the key is additive and `min` stays 1.
- **Negative**: LiteLLM joins one more network per isolated entry. LiteLLM is reachable from
  there with the key the add-on's service holds; the model key of a module carries only
  the models it needs (docs/model-gateway.md).
- **Neutral**: the service on an isolated network resolves only LiteLLM and the add-on's
  own services on that network. Everything else, including DNS names of the core, is
  unknown there.

## How a later generation may widen the list

A service joins `ISOLATED_ATTACHABLE` only with a new contract generation and a new
decision record that names the service, why a process reading foreign content needs it,
and what that process can do with it. The snapshot test fails until the set, the
generation table and the record agree. Narrowing the list breaks add-ons that use the
removed service and needs a breaking generation (`min = current`).

## Alternatives considered

- **Attach LiteLLM to `app_network`.** Rejected: the reading service shares that network
  with every attached core service and every other service of the add-on.
- **A separate add-on for the reading service.** Rejected: its `app_network` has the same
  problem, and splitting a module into two add-ons for one process adds install and
  upgrade steps without adding isolation.
- **Let the add-on name any attachable core service on an isolated network.** Rejected: the
  point of the network is that the list is short and fixed; an open list makes "isolated"
  a matter of each manifest.

## References

- [ADR 0002](0002-addon-core-compatibility-gating.md) — contract generations and the gate
- [docs/isolated-networks.md](../isolated-networks.md) — the add-on author's guide
- [docs/architecture.md](../architecture.md) — the manifest reference and Seam 1
- [docs/egress.md](../egress.md) — the egress network, the same rules for its name
