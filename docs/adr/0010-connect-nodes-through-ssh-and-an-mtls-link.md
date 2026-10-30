---
adr: 0010
title: Run node commands through an SSH forced command and connect services through an mTLS link gateway
status: Proposed
date: 2026-10-30
deciders:
  - fwahl711
tags:
  - topology
  - security
  - networking
  - papaia-ctl
supersedes: null
superseded_by: null
---

# 0010. Run node commands through an SSH forced command and connect services through an mTLS link gateway

## Context

ADR 0009 places services on several nodes. Two things are then missing:

- a way for the controller to run commands on another node without handing out a
  root-equivalent login (membership in the Docker group is root-equivalent), and
- a way for every service to keep its address (`litellm:4000`, `keycloak:8443`,
  `librechat:3080`) across the node boundary, without prompts, document text and API keys
  crossing the customer's network in clear text.

## Decision

**Control channel: SSH with a forced command.**

- On each node an unprivileged user `papaia` belongs to the Docker group. Its only
  `authorized_keys` entry is
  `restrict,from="<controller>",command="bash <root>/checkout/tools/papaia-ctl node-shell --node-root=<root>"`.
  The forced command narrows what the key is used for, but it is not a sandbox against
  the key's holder: installing a release or a bundle, which is the channel's job, can
  replace the shim itself. The controller's key is therefore as powerful as the controller
  and is kept like the CA keys next to it.
- `papaia-ctl node-shell` (`tools/lib/node_shell.py`) reads `SSH_ORIGINAL_COMMAND` and
  parses it itself, without a shell. Words are restricted to a small character set, and only
  an allowlist of verbs exists: `ping`, `version`, `status`, `doctor`,
  `compose-up|down|stop|restart|ps|pull|logs`, `bundle-put`, `checkout-put`, `image-load`,
  `hook`. Service and hook names are checked against the node's bundle. A caller cannot pass
  a path.
- Uploads arrive on stdin with a size limit. Archives are checked member by member (no
  absolute names, no `..`, no links, no devices, a cap on expansion) before anything is
  written. A bundle must name this node and is installed only once it is complete. The
  checkout is a `git archive` of the release, installed side by side and switched with an
  atomic symlink swap, so the node needs no Git and no GitHub access.
- Output streams, exit codes pass through, and every call leaves one line in the node's
  audit log.
- One Ed25519 key pair per node. The private key stays in the controller's config tree
  (`nodes/<name>/ssh/`, mode 0600) and never enters a bundle. The node's host key is pinned
  at enrolment, with its fingerprint shown and confirmed.
- An executor abstraction in `tools/lib/executor.py` has `local` (the controller's own node,
  through the same shim) and `ssh`. A resident node daemon could be added later as a third
  type.
- A node is enrolled either through a one-time admin session (the operator's own login runs
  the install script with `sudo`, and nothing of it is stored) or through a join archive the
  operator installs by hand. Both end in the same state.

**Service traffic: a link gateway on every node.**

- A new Compose fragment, `src/infra/link-gateway/`, with its own profile. It is never part
  of `src/docker-compose.yml` and is added with `-f` on the nodes of a distributed
  installation only. One HAProxy container per node runs in TCP mode.
- A static edge table (caller, target, address, port, purpose, required), together with the
  placement, generates each node's configuration. An edge whose two ends share a node
  produces nothing.
- **Caller side:** for every service on another node, the gateway carries the service's name
  as a network alias on `papaia-net` and listens on its usual port. It opens TLS to the
  peer's link port with its client certificate, verifies the peer against the link CA, and
  sets SNI to the service name. It also checks the peer's certificate against that name.
- **Target side:** one link port per node (7443 by default), published on the node's
  address only. It requires a client certificate of the link CA, routes by SNI to the local
  service, and has an ACL per client node derived from the edge table.
- The inner protocol is not touched, so HTTP, WebSocket and SSE pass through, and so does
  Keycloak's own certificate for the name `keycloak`. Where the proxy runs on another node,
  the gateway also carries the public auth host name and passes it to the proxy's port 443.
  Server-side OIDC discovery then needs no split DNS.
- `timeout tunnel` is one hour, with TCP keepalive and health checks. The gateway fails
  closed: a peer that is down means a refused connection, and no backend has a server
  without TLS.
- **The link CA is separate from the Keycloak CA.** Its key stays on the controller. A node
  receives its own leaf (with its name, its address and the names it serves) and the CA
  certificate. `papaia-ctl node renew-link` issues a new leaf.
- `papaia-ctl topology firewall` prints the connections the installation opens: SSH from
  the controller to each node, and the link port wherever a node calls a service on
  another. papaia never applies firewall rules itself.

## Consequences

- **Positive**: The node's login cannot be used for anything but the shim, only from the
  controller's address, and every call is in the node's audit log.
- **Negative**: Whoever holds the controller's key for a node controls that node: a release
  or a bundle pushed with it can replace the shim. Protecting the controller's config tree
  protects the nodes; nothing on the node can make up for a compromised controller.
- **Positive**: No service, no configuration file and no add-on contract changes for the
  distributed case. Every service dials the name it always dialled.
- **Positive**: The gateway configuration and the firewall matrix come from one table, so
  the rules an operator opens are the connections the gateways make.
- **Negative**: Two remote services on the same port cannot be reached from one node, since
  the gateway has one address there. Validation refuses such a placement and names both
  services.
- **Negative**: The nodes need Python 3.10 with PyYAML, because the shim is Python.
- **Neutral**: The shim's tests cover the allowlist, argument injection, path traversal and
  oversized uploads. The gateway's tests run two real HAProxy processes where the binary is
  available. A two-machine run is still recorded separately (see
  `docs/distributed-validation.md`).

## Alternatives considered

- **A resident node daemon with mTLS** — a larger attack surface at the edge and a new
  long-running component to operate and update.
- **Docker over SSH (`DOCKER_HOST=ssh://`)** — bind mounts, the backup helpers and the
  runner's self-lookup assume a local daemon, and it is root-equivalent with no verb
  allowlist.
- **The Docker API behind a socket proxy** — still a root-equivalent API, filtered per
  endpoint rather than per operation.
- **`extra_hosts` with identical ports** — no TLS, no authentication, and port collisions on
  the host.
- **Parametrising every service URL** — touches many files and the add-on contract.
- **A Swarm overlay** — needs bidirectional cluster ports and Swarm membership at the edge.
- **A WireGuard network built by papaia** — needs host root or `NET_ADMIN`, an IP plan and
  key distribution. The customer provides the network, and the link provides the
  encryption.

## References

- ADR 0009 — topology model and placement.
- `tools/lib/node_shell.py`, `tools/lib/executor.py`, `tools/lib/nodes.py`,
  `tools/lib/link.py`, `src/infra/link-gateway/`.
