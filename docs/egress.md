# The single exit: papaia-egress

Everything that leaves the stack for the outside goes through one service, `papaia-egress`
(profile `egress`). The profile is always on: `papaia-ctl setup` (and with it `upgrade`) adds it
to `COMPOSE_PROFILES` whenever it is missing.

```
service --> egress network of its add-on --> papaia-egress --> [corporate proxy] --> outside
            (internal: true)                  allow list,
                                              protected hosts
```

## What it does

- **Only tunnels.** The proxy accepts HTTP `CONNECT host:port` and nothing else. TLS stays end to
  end between the service and its target; the proxy sees host and port, never content.
- **Allow list per source.** A source is one add-on. A connection is allowed only when
  `host:port` is on the allow list of the add-on whose egress network it arrived on, and the
  connecting container sits in the subnet of that network (a container elsewhere that routes to
  the proxy's address on another add-on's network is refused as an unknown source). Host names
  are compared exactly (no wildcards); an IP address only matches the same address.
- **Protected hosts win.** Hosts in `$PAPAIA_CONFIG_DIR/security/protected-hosts.yaml` are
  refused for every source, whatever an allow list says. Names are compared by name and by the
  addresses they resolve to; address ranges cover every address in them. See
  [Protected hosts](#protected-hosts-operators) for how names are resolved.
- **Never reached:** loopback, link-local (including the metadata address 169.254.169.254),
  multicast and unspecified addresses; the proxy's own addresses; its gateways; and every
  network the proxy is attached to apart from its exit network, that is the egress networks of
  all add-ons. An add-on can therefore not reach another add-on's services, the proxy's
  gateways, or the proxy under another add-on's alias. The Docker host's other addresses (its
  LAN and public addresses, its addresses on other Docker networks such as the gateway of
  `papaia-net`) are not known to the proxy and are not blocked by this rule: list them in
  `security/protected-hosts.yaml` (see [Protected hosts](#protected-hosts-operators)).
- **Internal addresses only when the operator opens them.** An address that is not global
  (RFC 1918, carrier-grade NAT `100.64.0.0/10`, `198.18.0.0/15`, unique local `fc00::/7`,
  site-local `fec0::/10`, documentation ranges, ...) is refused, even when an allowed name resolves to it (DNS
  rebinding, a Docker service name). The operator can open ranges for single add-ons (see
  [Internal targets](#internal-targets-operators)); an add-on manifest cannot. IPv4 addresses
  embedded in IPv6 (IPv4-mapped `::ffff:0:0/96`, IPv4-translated `::ffff:0:0:0/96`, NAT64
  `64:ff9b::/96`, 6to4 `2002::/16`) are judged, and compared with the protected hosts, like the
  IPv4 address itself.
- **No resolver for strangers.** Names that are not on the allow list of the source are not
  resolved, so the proxy cannot be used to send data out through DNS. The proxy connects to the
  address it checked.
- **Fails closed.** No add-on with an egress network: nothing leaves. A configuration the proxy
  cannot read: nothing leaves until it is fixed. A proxy that cannot read its own addresses
  and networks from the kernel: nothing leaves. A connection from any other network (for
  example a core service on the proxy's own network): refused. A protected name that cannot be
  resolved: its last known addresses stay protected, and no opened internal range is used
  until it resolves again.

`papaia-egress` is not on `papaia-net` and publishes no port. It sits on its own network with a
route to the outside and on the egress network of each add-on that declares one.

## Declaring an egress network (add-on authors)

An add-on that needs the outside creates an `internal: true` network in its own compose file,
puts the services that need the outside on it (and only there for their way out), and declares
it in `papaia-app.yaml`:

```yaml
# docker-compose.yml of the add-on
networks:
  egress:
    name: ${PAPAIA_PROJECT:-papaia}-<name>-egress
    internal: true
```

```yaml
networks:
  egress:
    network: ${PAPAIA_PROJECT:-papaia}-<name>-egress
    allow:
      - host: api.example.org
        ports: [443]
```

The render checks the declaration and stops, naming the add-on, when

- the network name (after `${PAPAIA_PROJECT}` is resolved) does not start with
  `<project>-<name>-`, or is a core network (`DOCKER_NETWORK`, `papaia-net`,
  `papaia-egress-net`, also with the project prefix) or one of Docker's networks (`bridge`,
  `host`, `none`);
- it is the add-on's own `networks.app_network` (core services join that one through
  `attach` and would count as the add-on), or a network another add-on in `deployment.yaml`
  declares as its app network, egress network or isolated network
  ([isolated-networks.md](isolated-networks.md));
- the add-on's `docker-compose.yml` does not create it with `internal: true` (a network
  created elsewhere, `external: true`, is refused too): otherwise the add-on's services would
  reach the outside around the proxy;
- an allowed host is a single label (a service name inside the stack), starts with `egress-`
  or `papaia-`, or ends in `.docker.internal` or `.localhost`.

The declaration belongs to add-on contract generation 7: a core below it would install the
add-on with the declaration unread, so `addon check` reports such a core as incompatible.

`papaia-ctl` then:

1. renders the allow list into `$PAPAIA_CONFIG_DIR/infra/egress/egress.json` on every `setup`,
   `start` and `addon` operation; the proxy picks the change up within five seconds;
2. writes `$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.egress.override.yml`, which joins
   `papaia-egress` to that network under the alias `egress-<name>`.

The services reach the proxy as `egress-<name>:3128` (or `papaia-egress:3128`) and use it as an
HTTPS proxy, for example `HTTPS_PROXY=http://egress-<name>:3128`. A declaration that fails a
check stops the render with a message naming the add-on, and no add-on is attached to the proxy
until it is fixed.

The add-on's network must exist before the core joins it. The network is created by the
add-on's first start; `papaia-ctl addon start <name>` then recreates `papaia-egress` with the
new attachment, so the add-on's egress works right away. If that step fails (it warns and the
add-on keeps running) or the network is still missing, the add-on's egress stays closed until
`papaia-ctl start` runs (or `docker compose up -d papaia-egress` with the core's compose files
and overrides). As with the other add-on networks, `papaia-ctl start` starts the add-ons first
when given `--addons` and skips an override whose network is missing. In a distributed
installation the attachment is picked up by the next `papaia-ctl start` of the controller.

## Protected hosts (operators)

`$PAPAIA_CONFIG_DIR/security/protected-hosts.yaml` is created empty on the first render. Each
entry names a source system that no service may reach through the exit:

```yaml
- name: erp
  hosts: [erp-sql.example.local, 10.20.0.15/32]
  ports: [1433]
  catalog_entry: mssql.erp
```

| Field | Meaning |
|---|---|
| `name` | Short name, lower case (`a-z`, `0-9`, `-`, `_`, `.`) |
| `hosts` | Host names, IP addresses or address ranges (CIDR). Required, not empty |
| `ports` | Optional. The proxy refuses the hosts on every port; the ports are for routes that bypass the exit |
| `catalog_entry` | Optional. The catalog entry the system belongs to. `mssql.<name>` makes the entry a SQL source: `mcp-mssql` then reaches it directly over `papaia-sql-uplink`, limited by host rules to these addresses and ports ([network.md](network.md)); such an entry needs `ports` and an IPv4 address |

Unknown fields, wildcards and malformed entries stop the render, so a typo never turns into a
missing protection.

Host names are resolved by the proxy in the background, every 30 seconds and right after a new
configuration (each lookup gives up after five seconds, so a slow resolver never holds up a
request). Every address a name was seen with stays protected until the configuration changes.
While a protected name has no answer (not yet resolved, resolver failing), the proxy uses no
opened internal range for any add-on, since the host may sit inside it under an address not
known yet; global targets are not affected. List a protected system by its addresses or ranges
as well as by its name, so its protection never depends on DNS.

Also list the Docker host's own addresses here (its LAN address, its public address, and the
gateways of the core Docker networks such as `papaia-net`): the proxy blocks only its own
gateways by itself, and an opened internal range or an allow-list entry would otherwise reach
the ports the stack publishes on the host.

After editing the file, run `papaia-ctl start` (or any `addon` command) to
render it; the running proxy applies it within five seconds of the render.

## Internal targets (operators)

`$PAPAIA_CONFIG_DIR/security/egress-internal-targets.yaml` is created empty on the first
render. An entry opens address ranges inside the company network for the add-ons it names:

```yaml
- name: company-llm
  ranges: [10.20.30.0/24]
  addons: [my-addon]
```

| Field | Meaning |
|---|---|
| `name` | Short name, lower case (`a-z`, `0-9`, `-`, `_`, `.`) |
| `ranges` | IP addresses or address ranges (CIDR). Required, not empty |
| `addons` | The add-ons that may reach them. Required, not empty |

The add-on still needs the host on its allow list, the protected hosts still win, and the
proxy itself, its gateways and the egress networks of the add-ons stay unreachable whatever
range is opened. Unknown fields and malformed entries stop the render.

An opened range must not contain the Docker host's own addresses (for example its LAN address
in `192.168.0.0/16`); otherwise every port the stack publishes there (Keycloak, LiteLLM, the
manager, Qdrant, the reverse proxy's admin port) becomes reachable through the exit. Open the
narrowest range that holds the target, or list the host's addresses in
`security/protected-hosts.yaml`, which wins over every opened range.

## Corporate proxy

When the outside is only reachable through a proxy of the company network, set in
`$PAPAIA_CONFIG_DIR/.env`:

| Variable | Meaning |
|---|---|
| `PAPAIA_EGRESS_UPSTREAM_PROXY` | `http://host:port` or `http://user@host:port`. The password of the user goes into `$PAPAIA_CONFIG_DIR/infra/egress/upstream-proxy-password` (mode 0600), never into the URL |
| `PAPAIA_EGRESS_NO_PROXY` | Comma-separated host names `papaia-egress` connects to directly; a name covers its subdomains. The allow lists still apply |

Only `papaia-egress` uses the corporate proxy; no other container gets proxy variables. When
the name resolved inside the stack, `papaia-egress` asks the corporate proxy for a tunnel to the
addresses it checked, one after another until one is reached, not to the name, so the corporate
proxy cannot resolve the name to another address. A name that does not resolve inside the stack is checked by name only: the corporate
proxy resolves it, and the address checks of this page (protected ranges, internal addresses)
do not apply to its answer. Keep such names off the allow lists unless the corporate proxy
itself keeps them from internal addresses.

## Audit

Each decision is one JSON line on the proxy's standard output in the shape of `papaia.audit/1`:
`operation` `connect`, `effect` `send`, `result` `allowed` or `denied`, `error_code`
(`not_allowed`, `protected_host`, `blocked_address`, `unknown_source`, `unresolvable`,
`bad_request`, `too_many_connections`), and `detail` with source, host and port (host and port
are empty for a request that could not be read). A refused protected host has the event
`protected_host_denied`. The correlation id is taken from the request header
`X-Papaia-Correlation-Id` when it is valid (at most 64 characters `A-Z a-z 0-9 -`), otherwise a
new one is generated. Content, credentials and tokens are never written.

```sh
docker compose logs papaia-egress | grep '"format": "papaia.audit/1"'
```

A refused tunnel is answered with `403` (`400`/`405` for a malformed request, `503` over the
connection limit) and the header `X-Papaia-Error: <error_code>`, so the calling service can show
why.

## Limits

- Only `CONNECT`. Plain-HTTP proxying and protocols that cannot be tunnelled through an HTTP
  proxy (for example SMTP from Postfix) do not go through this service.
- The allow lists come from the add-on manifests. The one core source is LiteLLM in a test
  stack with the hosted test model switched on ([hosted-test-model.md](hosted-test-model.md)).
  Lists maintained at run time by a module, and the other outbound routes of core services
  (identity federation, SIEM export), are not part of this release.
- At most 512 connections at a time, 128 of them from one add-on; a tunnel without traffic in
  either direction for five minutes is closed. One add-on cannot use up the exit of the others.
- In a distributed installation the service runs on the controller, next to the add-ons.
