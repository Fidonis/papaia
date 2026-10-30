# Running papAIa on several machines

papAIa normally runs on one host. A **distributed installation** spreads the core services
over several machines (nodes). Use it when ingress, identity and the LLM gateway have to sit on
a machine at the network edge (a DMZ) and the application and its data behind it. This guide
covers planning, setup, operations and recovery. The design is recorded in
[ADR 0009](adr/0009-place-services-on-nodes-with-a-topology-block.md) and
[ADR 0010](adr/0010-connect-nodes-through-ssh-and-an-mtls-link.md).

## What you plan

**Nodes.** One node is the **controller**: the machine you run `papaia-ctl` on. It keeps the
configuration directory, the CA keys and the SSH keys, and runs papaia-manager and the RAG
system. Every other node is reached over SSH and holds only what its own services need.

**Placement.** Every core service runs on exactly one node. The services that can be placed:

| Service | Runs | Must run |
|---|---|---|
| `nginx` | Nginx Proxy Manager, its auth sidecar, oauth2-proxy | anywhere |
| `keycloak` | Keycloak and its database | anywhere |
| `litellm` | LiteLLM, its database, Prometheus | anywhere |
| `librechat` | LibreChat, MongoDB, Meilisearch, the vector database, the RAG API | anywhere |
| `websearch` | SearXNG, Firecrawl, MCP-Firecrawl, the Jina reranker | with `librechat` |
| `localai` | LocalAI and its model download | on a node with the GPU its image needs |
| `rag` | Qdrant, its MCP server, the ingester, Tika | on the controller |
| `smtp` | the mail relay | anywhere (best with `keycloak`) |
| `manager` | papaia-manager | on the controller |

Two presets cover the common split into an edge node and an internal node:

- `dmz-split` — Nginx Proxy Manager, Keycloak, the mail relay and LiteLLM at the edge.
- `dmz-edge` — Nginx Proxy Manager and LiteLLM at the edge; Keycloak stays internal.

**Public URLs.** The bundled proxy serves every public URL by host name from its node, so each
URL is a host name without a port (`https://chat.example.org`, `https://auth.example.org`).

**Prerequisites on every node:** Docker with the compose plugin (2.20 or newer), Python 3.10
or newer with PyYAML, an SSH server. The nodes' clocks have to be synchronized: tokens carry
`exp` and `nbf`, and a node minutes off refuses every sign-in.

## The topology file

The topology lives in `deployment.yaml` of the configuration directory. A file with the same
block is the reviewable way to set it up:

```yaml
topology:
  mode: distributed
  controller: internal
  link:
    port: 7443
  nodes:
    internal:
      address: 10.0.2.10
      executor: local
    edge:
      address: 10.0.1.10
      executor: ssh
      ssh: {user: papaia, port: 22}
      root: /srv/papaia-node
      gpu: none
  placement:
    nginx: edge
    keycloak: edge
    smtp: edge
    litellm: edge
```

```sh
tools/papaia-ctl topology validate     # names every problem before anything changes
tools/papaia-ctl topology show
```

## Setting it up

A distributed installation is set up as a **new** installation. An existing single-host
installation keeps its shape (`setup --topology=distributed` refuses it and changes nothing).
To move one onto several machines, set the distributed installation up in a new configuration
directory and bring the data over with `backup` and `restore --only=...`.

```sh
tools/papaia-ctl setup --config-dir=/srv/papaia-config \
  --app-host=https://papaia.example.org --auth-host=https://auth.example.org \
  --librechat-host=https://chat.example.org --litellm-host=https://llm.example.org \
  --topology-file=topology.yaml
```

Interactively, `setup` asks "on this machine or on several machines" and then for the
machines, the preset or a node per service, and the link port. It then prints the topology and
the firewall rules, and writes a join archive for every node that is not enrolled yet.

### Enrolling a node

On the controller `node add` (or `setup`) writes a **join archive**: the checkout, an install
script, the node's `authorized_keys` line and the fingerprint of the controller's key. On the
node, as root:

```sh
tar -xzf papaia-join-edge.tar.gz
sudo ./papaia-join-edge/install.sh
```

The script creates the unprivileged user `papaia` (in the Docker group), the node directory
(`/srv/papaia-node`) with the first checkout, and an `authorized_keys` entry that allows the
controller's key exactly one command, from the controller's address only. It prints the node's
SSH host key fingerprints. Back on the controller:

```sh
tools/papaia-ctl node check edge   # shows the host key fingerprint; confirm it against the script's
tools/papaia-ctl start
```

With an admin login on the node, `node add edge --address=10.0.1.10 --bootstrap=admin
--admin=you@10.0.1.10` does the same in one step. Your login and `sudo` are used once and
nothing of them is stored.

## The firewall

```sh
tools/papaia-ctl topology firewall [--format=table|json|csv]
```

This lists every connection between the nodes. For `dmz-split`:

| From | To | Port | What |
|---|---|---|---|
| internal | edge | 22/tcp | control channel (SSH, forced command) |
| internal | edge | 7443/tcp | link: keycloak, litellm, the public auth host |
| edge | internal | 7443/tcp | link: librechat, localai, papaia-manager, qdrant |

Plus 80 and 443 from the users to the proxy's node. papaia never changes a firewall; open
exactly these. `doctor` names a missing rule when a link cannot be reached.

## Daily operations

| Command | In a distributed installation |
|---|---|
| `start [--node=NAME] [--addons]` | Renders, hands each node its release and bundle, then starts in order: link gateways, Keycloak and the mail relay, LiteLLM, the application, the proxy last. A failing node stops the sequence and is named. |
| `stop [--node=NAME] [--clean-up] [--addons]` | The same order backwards. |
| `status [--json]` | One report, a section per node; JSON adds `node` and `nodes`. |
| `doctor [--json]` | The controller's checks plus `nodes` (each node's own checks, version skew, clock) and `links` (a TLS handshake per link, certificate expiry). |
| `node list --check` | Every node, its address, its services, whether it answers. |
| `node renew-link NAME` | A new link certificate for the node; `doctor` warns 30 days before one expires. |

Each node writes one line per command it receives, refused ones included, to
`<root>/audit.log`.

## Backups

```sh
tools/papaia-ctl backup [--only=node:edge|module:NAME|volume:NAME|addon:NAME]
tools/papaia-ctl restore [--restore-point=ID] [--only=...]
```

A restore point holds the whole installation and is stored on the controller, in the same
catalogue as on one host:

- the controller's configuration directory (every node's bundle, the CA and SSH keys),
- every named volume of every node, streamed from the node (its writers paused meanwhile),
- the state a remote node keeps itself (the proxy's database and certificates),
- the data of add-ons placed on a node.

Nothing stays at the edge, and secrets do not pile up there.

**A restore point is not one moment across nodes.** The nodes are archived one after another,
so Keycloak's database and LibreChat's can be a few minutes apart. That is the same as restoring
one of them on its own: an account created in between exists in Keycloak but not yet in
LibreChat, and LibreChat creates it again at the next sign-in.

`restore --only=node:edge` puts back the data of the edge node only: it stops the services
there whose data it replaces, writes the data back and starts them, and touches no other node.
A whole restore stops every node, puts the configuration back, hands every node its bundle and
release again, writes back each node's data and starts the installation. Restore points of a
single host are refused in a distributed installation, and the other way round.

## Upgrades

```sh
tools/papaia-ctl upgrade [--version=X.Y.Z] [--dry-run]
```

All nodes move to the same release in one run ("stop the world"):

1. Every node has to answer, or nothing starts.
2. A restore point of the whole installation is taken (unless `--no-backup`).
3. The installation is **locked**, then stopped on every node, and the controller's checkout
   moves to the release.
4. Every node gets the release. Each migration runs where its data lives: a migration that
   reshapes a service's data runs on that service's node, the others on the controller. The
   ledger records which node ran each one.
5. The configuration is rendered again and the installation starts in order. The lock is
   released.

While the lock is set — and whenever a node runs another release than the controller —
`start`, `backup`, `setup` and the add-on commands that start or stop containers refuse with the
reason. What still works: `upgrade` itself, the way back (`restore`), `stop`, `status`, `doctor`
and the `node` commands.

The lock is taken once every node is stopped and released as soon as the releases agree
again: when the upgrade finishes, when its last step (the start) fails, or when moving the
checkout fails. A retried `upgrade` is not held up by it.

If the upgrade fails, it prints the way back for the controller and for each node:
`git checkout` of the previous tag and `restore --restore-point=ID`. The restore puts the
configuration back, and with it every node's previous release. After an upgrade with
`--no-backup` there is no restore point; `start --addons --unlock` releases the lock and puts
the checkout's release back on every node.

## Add-ons

An add-on attaches to core services through a Docker network, and a network exists on one node
only. So an add-on runs on the node of every core service it attaches to:

```sh
tools/papaia-ctl addon install docs --path=../papaia-addons/docs [--node=NAME]
```

Without `--node`, the add-on goes to the node of the services it attaches to (or the
controller). An add-on that attaches to services on two nodes is **not placeable**. The
compatibility gate refuses it, and no `--force` changes that. An add-on on a remote node travels
in that node's bundle, and `start --addons`, `addon start` and `addon stop` run it there.
`ADDON_API` and the manifest contract are unchanged.

## Security notes

- **The edge is the trust anchor of whatever runs there.** With Keycloak at the edge, a
  compromised edge node can issue tokens for every service. Choose `dmz-edge` when identity has
  to stay internal.
- **The LLM gateway sees everything sent to a model.** With LiteLLM at the edge, prompts and
  the document text that RAG and the add-ons hand to a model pass through the edge node.
- **The control channel.** The `papaia` user is in the Docker group, which is root-equivalent.
  Its key can run only `papaia-ctl node-shell`, only from the controller's address. The shim
  accepts a short list of verbs, checks every name against the node's bundle, and logs every
  call. It is not a sandbox against the key's holder, though: installing a release or a
  bundle, which is what the channel is for, can replace the shim itself. **Whoever holds the
  controller's configuration directory controls every node.** Protect it like the CA keys it
  contains, and keep the backups that contain it just as tight.
- **Between the nodes** every service connection is mutual TLS with a CA of its own, separate
  from Keycloak's. Its key never leaves the controller, and each node only reaches the services
  the edge table allows it. A peer that is down means a refused connection, never clear text.
- **What a node holds:** its own services' env files, configuration and certificates, its link
  certificate and key. No secret of a service on another node, no CA key, no SSH key.

## Recovering the controller

Everything the installation needs, except the node data, is in the controller's configuration
directory, and every restore point holds that directory. To rebuild a lost controller:

1. Prepare a new machine with the controller's address (the nodes accept the controller's key
   from that address only), Docker, and a papAIa checkout of the installed release next to
   where the configuration directory goes.
2. Unpack the configuration directory of the latest restore point:
   `tar -xzf <backup dir>/<id>/papaia-config.tar.gz -C /srv/papaia-config`. It holds the SSH
   keys, the pinned host keys and the link CA, so the nodes accept the new controller as before.
3. `papaia-ctl doctor --config-dir=/srv/papaia-config` checks the nodes and the links, and
   `papaia-ctl start` brings the installation up again.
4. The controller's own data (its volumes) comes back with
   `papaia-ctl restore --restore-point=<id> --only=node:<controller>`.

Keep the backup directory off the controller (a mount from elsewhere), or it is lost with it.

## Limits

- No high availability: every service runs once, on one node. A node that is down takes its
  services with it.
- No live migration: setup does not move an existing installation onto several machines, and
  placement does not change for a running installation. Moving a service means a new
  installation and a restore.
- Two services on other nodes that use the same port cannot both be reached from one node, since
  the gateway has one address there. Validation refuses such a placement.
- Rolling upgrades are not supported. All nodes move together, and the installation is down for
  the duration.

## Checking it on real machines

[Validating a two-node installation](distributed-validation.md) is the hand-run check of all of
this on two VMs with a firewall between them.
