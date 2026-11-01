# Link gateway

Only used by a distributed installation (see `docs/distributed.md` and
`docs/adr/0010-connect-nodes-through-ssh-and-an-mtls-link.md`). A single-host installation
never loads `docker-compose.yml` in this directory: it is not part of the `include:` list of
`src/docker-compose.yml`.

Every node of a distributed installation runs one gateway container. It lets every
service keep its usual address (`keycloak:8443`, `litellm:4000`, `librechat:3080`) on
every node:

- **Caller side.** For each service that runs on another node, the gateway carries the
  service's name as a network alias on `papaia-net` and listens on the service's port. It
  opens mutual TLS to the link port of that node with its own client certificate, checks
  the peer's certificate against the link CA and sets SNI to the service name.
- **Target side.** One link port per node (7443 unless `topology.link.port` says
  otherwise), published on the node's address only. A client certificate of the link CA
  is required. Routing goes by SNI to the local service, and each client node reaches only
  the services the edge table in `tools/lib/link.py` allows it.

The connection inside the tunnel is passed through untouched (TCP mode), so HTTP,
WebSocket, SSE and Keycloak's own TLS work as they do on one host. A peer that is down
means a refused connection; there is no clear-text fallback.

Nothing here is edited by hand. `papaia-ctl` generates the node's `haproxy.cfg`, its
certificates and the Compose override on every render, into the node's bundle
(`$PAPAIA_CONFIG_DIR/nodes/<node>/bundle/link/`). The link CA is separate from the
Keycloak CA, and its key stays on the controller (`$PAPAIA_CONFIG_DIR/link-ca/`).
`papaia-ctl node renew-link <node>` issues a new leaf certificate.
