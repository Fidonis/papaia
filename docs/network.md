# Network routes and the communication matrix

Every connection the installation makes or accepts is a row of one file,
[`security/comm-matrix.yaml`](../security/comm-matrix.yaml): inbound to the edge, between the
Docker networks, made by the Docker host itself, and outbound. `papaia-ctl topology firewall`
prints it with the targets of the installation, `papaia-ctl doctor network` checks the one
direct route against the host, and this page explains it. There is no second, hand-kept list.

## The rows

Each row names `id` (`K-01` …), `direction` (`inbound`, `internal`, `outbound` or `host`),
`from`, `from_network` (the network the connection leaves its source on, without the Compose
project prefix), `to`, `ports`, `protocol` (`tcp`, `udp` or `file`), `purpose`, `when` and
`required`. A row that leaves the stack also names its way, `via`:

- `egress` — through the single exit `papaia-egress` ([egress.md](egress.md)), with the allow
  list of its source and the protected hosts in force;
- `direct` — without the exit. Only three rows may: the backup target (K-12) and the audit
  chain heads (K-15), both file system targets, and the SQL source (K-14).

A row with `pending` names what is still missing before its way holds in this release (for
example, SMTP cannot be tunnelled through the exit, so the mail relay still sends directly).
The file is checked strictly: unknown fields, a missing `via`, a direct route other than the
three above or a malformed port stop every command that reads it.

The operator's model server is row K-20: LiteLLM reaches a model server that papaia does not
run only through the exit, and `setup` says so in its summary:

```
Model source: outside the installation (models.example.org:443).
  Inhalte der Anfragen verlassen Ihr Netz. Prüfen Sie Auftragsverarbeitung und Übermittlung.
```

Every model server papaia does not run counts as outside, also one in the company network. In
this release the only such route is the hosted test model of a test stack
([hosted-test-model.md](hosted-test-model.md)); otherwise the summary reads `Model source:
inside the installation`.

## The direct route to the SQL source (K-14)

A SQL source is a protected host whose catalog entry is `mssql.<name>`, in
`$PAPAIA_CONFIG_DIR/security/protected-hosts.yaml` ([egress.md](egress.md#protected-hosts-operators)):

```yaml
- name: erp
  hosts: [erp-sql.example.local, 10.20.0.15/32]
  ports: [1433]
  catalog_entry: mssql.erp
```

Such an entry needs `ports` and at least one IPv4 address or range (from /16): the host rules
work on addresses, not names. `papaia-egress` refuses it for every source, as every protected
host. Then, and only then:

1. **The network.** `mcp-mssql`, the service of the SQL add-on, joins the network
   `<project>-sql-uplink` (`papaia-sql-uplink` for the project `papaia`) next to the networks
   it already has. The network is not internal and has the fixed range
   `PAPAIA_SQL_UPLINK_SUBNET` (default `10.255.254.0/29`, a private IPv4 range from /24 to
   /29 that must not overlap a SQL source). It is IPv4 only (`enable_ipv6: false`, also when
   the Docker daemon turns IPv6 on for new networks by default) and its bridge on the host
   has the fixed name `psql-<id>`, so the host rules can match the interface. `papaia-ctl` writes the override
   `$PAPAIA_CONFIG_DIR/overrides/addons/docker-compose.<add-on>-sql-uplink.override.yml` on
   every `setup`, `start` and add-on operation and removes it with the SQL source or the
   add-on. No other service ever joins the network, and more than one active add-on with a
   service `mcp-mssql` stops the render.

   Every other network of `mcp-mssql` must be internal (`internal: true` in the add-on's
   compose file). Docker gives a container its default route on a network that is not
   internal; on a second such network the SQL traffic would leave with a source outside the
   uplink range, the host rules would drop it, and the route would not work. `doctor network`
   reports that case as `fail`.
2. **The host rules.** `papaia-ctl` writes
   `$PAPAIA_CONFIG_DIR/security/sql-uplink-rules.sh`. Load it as root on the Docker host after
   `setup` and after every change of the SQL sources:

   ```sh
   sudo sh "$PAPAIA_CONFIG_DIR/security/sql-uplink-rules.sh"
   ```

   It replaces the installation's own chain `PAPAIA-SQL-<id>` in one step
   (`iptables-restore --noflush`) and puts the jump to it first in the chain `DOCKER-USER`,
   which Docker evaluates before its own rules
   ([Docker documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/)):

   | From | To | Rule |
   |---|---|---|
   | the uplink range, entering on the bridge `psql-<id>` | each listed address, each listed port (TCP) | allowed |
   | the uplink range on any other interface (a forged source) | anything | dropped |
   | the bridge `psql-<id>` | anything else | dropped |
   | any other container | a listed address | dropped |
   | any other container | a listed port (TCP) | dropped |

   The last rule has an effect beyond the installation: `DOCKER-USER` sees all traffic the
   host forwards, so it also drops forwarded TCP traffic to a listed port (for example 1433)
   that has nothing to do with papaia, such as another installation's or another container's
   connection to a SQL Server elsewhere, traffic to a port published on the host with that
   number, and traffic between containers on one bridge when `br_netfilter` passes bridged
   traffic through iptables. Run other SQL clients on this host only through a SQL source of
   this installation, or on another host.

   papaia never changes the host firewall itself: the commands that do run as root, papaia-ctl
   does not. On Docker Desktop the chain lives in Docker's VM.

   The rules live in the running kernel only and are gone after a reboot of the host (on
   Docker Desktop: after a restart of its VM). Until they are loaded again nothing narrows the
   uplink: `mcp-mssql` reaches any address and other containers are not kept away from the
   SQL source. `doctor network` reports `fail` (`host rules not loaded`) in that state. Load
   the file again after every boot, for example with a systemd unit that runs after
   `docker.service`:

   ```ini
   # /etc/systemd/system/papaia-sql-uplink-rules.service
   [Unit]
   Description=Host rules of the papaia SQL uplink
   After=docker.service
   Requires=docker.service

   [Service]
   Type=oneshot
   ExecStart=/bin/sh /srv/papaia-config/security/sql-uplink-rules.sh

   [Install]
   WantedBy=multi-user.target
   ```

   Use the absolute path of `$PAPAIA_CONFIG_DIR` and enable it once with
   `sudo systemctl enable --now papaia-sql-uplink-rules.service`. Docker creates `DOCKER-USER`
   when it starts, so the unit must run after it. Saving the rules with `iptables-persistent`
   works too, but the file is then a second copy that must be saved again after every change
   of the SQL sources; the unit always loads the current file.
3. **The check.** `papaia-ctl doctor network` (part of every `doctor` run) compares:

   - the network: created, not internal, the rendered range and bridge name, no IPv6 (neither
     `EnableIPv6` nor an IPv6 range), no member other than `mcp-mssql` of the SQL add-on,
     and no other network of `mcp-mssql` that is not internal;
   - the host rules: `iptables -S` of the chain equals the rendered rules, in order, and the
     jump is the first rule of `DOCKER-USER`.

   A drifted, missing, misplaced or additional rule, another member or another range is
   `fail`, as are IPv6, another bridge and a second network with a route out. Rules that
   cannot be read (not root, no `iptables`, inside a container, Docker
   Desktop) are `warn` and say `not verified`; run `sudo tools/papaia-ctl doctor network` on
   the host. Without a SQL source the check reports `skip`.

To remove the route, delete the SQL source from `protected-hosts.yaml`, run `papaia-ctl
start`, and remove the chain:

```sh
sudo iptables -D DOCKER-USER -j PAPAIA-SQL-<id>
sudo iptables -F PAPAIA-SQL-<id> && sudo iptables -X PAPAIA-SQL-<id>
```

The chain's name is in the rules file and in `doctor network --json` (`details.chain`).

## `topology firewall`

```sh
tools/papaia-ctl topology firewall [--format=table|json|csv]
```

On one host it prints the rows of the matrix that leave the host: the ones that always apply,
and the configured targets of the mail relay (K-10), the SQL sources (K-14, one line per
address), the corporate proxy (K-18) and a model server outside the stack (K-20). Rows still
pending in this release are left out. Below the table come the host rules of the SQL source
and the command that loads them; `--format=json` gives `routes`, `host_rules` and
`rules_file`. In a distributed installation it lists the connections between the nodes
([distributed.md](distributed.md#the-firewall)).

Limits: the uplink is IPv4 only; IPv6 addresses of a SQL source are refused. The host rules
cover containers; the host's own processes are not filtered.
