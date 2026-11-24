# Joining the network another add-on offers

Contract generation 17 ([ADR 0027](adr/0027-join-the-network-an-add-on-offers-instead-of-its-app-network.md)).

An add-on that calls the interface of another add-on joins the network that add-on offers
for it, not its app network. The app network of an add-on carries its whole API, its
ingress and its other services; the offered network carries the service behind one of its
`exposes` entries, typically a relay.

## The key

In the consuming add-on's `papaia-app.yaml`:

```yaml
requires:
  addon_api: [17]                  # only generations from 17 on, see "Older cores"
  addons:
    - {name: papaia-flow, optional: true}
networks:
  app_network: ${PAPAIA_PROJECT:-papaia}-papaia-assist-net
  join_addons:
    - addon: papaia-flow           # from requires.addons
      services: [assist-gate]      # services of this add-on that join
      network: ${PAPAIA_PROJECT:-papaia}-papaia-flow-modules
```

The listed services join exactly `network`, next to the networks they have in the add-on's
own compose file, and never the target's `app_network`. The other services of the add-on
stay off it. `papaia-ctl` writes the join to
`overrides/addons/docker-compose.<name>-offer-<target>.override.yml` and hands it to the
add-on's compose project at `addon start`.

An entry without `network` joins the target's `app_network`, as since generation 4.

## What a target offers

The target add-on offers a network when all of this holds:

- its own `docker-compose.yml` declares the network with a `name` and `internal: true`
  (not `external`);
- the `address.service` of one of its `exposes` entries joins the network;
- the network is not its `app_network`, not its egress network and not one of its isolated
  networks.

The name follows the rule of `app_network` for the target:
`${PAPAIA_PROJECT:-papaia}-<target>-...` or its literal default `papaia-<target>-...`.

Example of the target side (papaia Flow):

```yaml
# papaia-app.yaml
exposes:
  - id: flow.runs
    address: {service: flow-module-relay, port: 8080}
    # ...

# docker-compose.yml
services:
  flow-module-relay:
    networks:
      flow-relay: {}
      flow-modules: {aliases: [papaia-flow-api]}
networks:
  flow-modules:
    name: ${PAPAIA_PROJECT:-papaia}-papaia-flow-modules
    internal: true
```

## Refusals

`papaia-ctl addon check`, `install`, `start`, `upgrade`, `rollback` and
`doctor addon_compat` refuse the consuming add-on, naming the entry
(`networks.join_addons[<i>]`), when:

- the entry has a field other than `addon`, `services` and `network`;
- `network` is empty, not scoped to the target, a core network or one of Docker's networks;
- the target's compose file does not create the network, or creates it without
  `internal: true`;
- no `exposes` entry of the target has its address on the network;
- the network is the target's `app_network`, egress network or an isolated network;
- another entry joins the same target's `app_network`;
- `requires.addon_api` names a generation below 17, or none.

These are malformed manifests: neither `--force` nor warn mode lets them through. A core
whose window ends below 17 reports the add-on `INCOMPATIBLE` and names generation 17 and
the entry.

## Older cores

A core before generation 17 does not know `network` and would read the entry as a join of
the target's app network. A manifest that uses the key therefore names only generations
from 17 on in `requires.addon_api` (for example `[17]`): the gate of an older core finds
no generation it serves and refuses the add-on as `INCOMPATIBLE`. That refusal is the
only barrier on such a core: with `--force` or in warn mode, a core older than 17 lets an
`INCOMPATIBLE` add-on through and turns the entry into a join of the target's app network.
Operators must never force a manifest that uses `network` on a core older than 17; the
current core cannot close this path for an older one.

## Absent or stopped target

- **Not installed or not active** (an optional requirement): the entry is skipped with a
  warning that names the target and the network. No override names the network; the
  add-on starts and only what the target adds is missing.
- **Active but stopped**: when the network does not exist at `addon start` (also within
  `papaia-ctl start` and `restore`), the offer override is left out with a warning, and
  the add-on starts without the join. `doctor addon_compat` reports the missing network.
  Start the target, then `papaia-ctl addon start <name>` again.
- **The target stops offering the network** (after an upgrade): the render drops the join
  with a warning naming the entry; the services join nothing instead.

Single host only: a network cannot span two nodes of a distributed installation.
