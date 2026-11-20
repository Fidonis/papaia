# Internal CA (`pki` profile)

The optional `pki` profile gives an installation one certificate authority for TLS between
its own services. Every module (papAIa studio, flow, assist, data, the other add-ons and core
services) gets its certificates from that one CA, in one layout, and trusts the same bundle.
The decision behind it is [ADR 0019](adr/0019-internal-tls-from-a-core-pki.md).

The profile is **off by default**. While it is off nothing changes: no key in `.env`, no
file, no container, no volume.

- [What it is for](#what-it-is-for)
- [Switching it on and off](#switching-it-on-and-off)
- [Asking for certificates](#asking-for-certificates)
- [What a service gets](#what-a-service-gets)
- [Renewal and restarts](#renewal-and-restarts)
- [A new CA](#a-new-ca)
- [Bring your own CA](#bring-your-own-ca)
- [Edge certificates stay separate](#edge-certificates-stay-separate)
- [Backup, restore and removal](#backup-restore-and-removal)
- [Distributed installations](#distributed-installations)
- [Relation to the KRITIS profile](#relation-to-the-kritis-profile)
- [Commands and settings](#commands-and-settings)

## What it is for

Behind the reverse proxy, services talk to each other over the Docker networks: an
application to its database, a gateway to its workers, LibreChat to an MCP server. On a
single host these links never leave the machine, and plain TCP is the default. Operators
of critical infrastructure (KRITIS, NIS2) are expected to encrypt and mutually
authenticate internal links as well, and some modules refuse to run without that:
papaia-studio, for example, does not start in its KRITIS mode without internal TLS.

A module could create its own CA, but then every module has its own trust anchor, its own
rotation and its own idea of where keys live, and an auditor sees as many CAs as there are
add-ons. The `pki` profile is the one place for it:

- **One CA per installation**, ECDSA P-256, `basicConstraints CA:TRUE, pathlen:0`. Its
  private key is in a Docker volume that only the one-shot issuer ever mounts.
- **Leaf certificates per service**, server and client, with the DNS names the service
  is reached under.
- **Automatic renewal** at two thirds of the lifetime (90 days by default), with a
  restart of what changed.
- **Rotation of the CA** without downtime of the trust: old and new CA are in the bundle
  until the last old certificate has expired.
- **Bring your own CA**: an intermediate of the company PKI, or certificates issued
  outside papAIa entirely.

## Switching it on and off

```bash
papaia-ctl setup --pki        # on; the wizard asks as well (default: no)
papaia-ctl setup --no-pki     # off; the issued files stay until `pki purge`
```

The choice is kept: a later `setup` without either flag leaves it as it is. Switched on,
`setup` adds `pki` to `COMPOSE_PROFILES`, writes `PAPAIA_PKI_DIR` to the root `.env`
(default `<PAPAIA_CONFIG_DIR>/pki`), records the profile in `deployment.yaml` and issues
the certificates right away when Docker answers.

`PAPAIA_PKI_DIR` can point elsewhere (an absolute path of its own; the config directory
itself or one of its parents is refused). Leaving it inside the config directory means it
is part of the config backup; moving it outside keeps the leaf keys out of what
papaia-manager mounts.

## Asking for certificates

An add-on asks in its manifest, `papaia-app.yaml`:

```yaml
pki:
  services:
    - name: papaia-studio-gateway      # a DNS label; the client certificate's CN
      uid: 10001                        # numeric user of the container that reads the files
      server:
        dns: [papaia-studio-gateway]    # names the service is reached under
      client: true                      # also a client certificate
    - name: papaia-studio-app-host
      uid: 10001
      client: true                      # client only: no `server`
    - name: papaia-studio-postgres
      uid: 70
      server:
        dns: [papaia-studio-postgres]
```

A core module asks the same way, in a `pki.yaml` next to its compose file:

```yaml
profile: rag            # honoured while this profile is on
pki:
  services:
    - name: qdrant
      uid: 1000
      server: {dns: [qdrant]}
```

Its certificates land under the module name `core`. The release ships no such file yet:
core services opt in one by one, each with its own change to its compose file.

The key is additive: a core without the profile, or an older core, ignores it, so an
add-on can carry it without raising its `requires.addon_api`. With the profile off,
`papaia-ctl start` mentions the add-ons that could use it.

## What a service gets

```
<PAPAIA_PKI_DIR>/
  ca-bundle.crt                 0444  every CA the services trust
  inventory.json                0444  what is issued (format papaia.platform-pki/1)
  <module>/                     0755
    <service>/                  0500, owned by the service's uid
      ca.crt                    0444  the same bundle
      tls.crt, tls.key          0444 / 0400  server certificate (when `server` is requested)
      client.crt, client.key    0444 / 0400  client certificate (when `client: true`)
      generation                0444  a counter, raised whenever something here changed
```

- Server certificates carry `extendedKeyUsage serverAuth` and the requested names, plus
  `localhost` and `127.0.0.1` for health checks inside the container.
- Client certificates carry `extendedKeyUsage clientAuth` and `CN=<service name>`; the
  peer authorizes by that name.
- Keys are ECDSA P-256. Certificates of an intermediate CA contain the chain up to (not
  including) the root.
- Files are replaced atomically, keys before certificates, the bundle after them and
  `generation` last. A reader that sees a new `generation` sees the complete set.
- With `PAPAIA_PKI_DIR` set, add-ons find it in the root `.env` (and in their environment
  where they map it), so a compose file can mount
  `${PAPAIA_PKI_DIR}/<module>/<service>:/run/secrets/tls:ro`. Consumers use TLS 1.3.

`inventory.json` lists the CAs (subject, SHA-256 fingerprint, end date, role `active`,
`next` or `retired`, source `pki`, `enterprise` or `external`) and every service with its
names, its generation and the end dates of its certificates.

## Renewal and restarts

The issuer runs on `setup`, `start`, `addon install|start|remove|uninstall` and
`papaia-ctl pki renew`. Each run:

1. issues what is requested and missing,
2. renews a certificate once two thirds of its lifetime have passed (day 60 of 90), or at
   once when its names, its kind or the issuing CA changed,
3. removes the directory of a service that is no longer requested,
4. restarts the running core services and add-ons whose files changed. A stopped one
   reads the new files when it starts.

A run that finds nothing to do changes nothing, not even a timestamp in a service
directory. To renew without waiting for a start, run `papaia-ctl pki renew` from a daily
timer; `pki renew --force` issues every certificate again.

`papaia-ctl pki status` lists every certificate with its days left and exits 1 when one
ends within 14 days or the inventory is missing; `papaia-ctl doctor` reports the same in
its `certs` check (warning under 14 days, failure under 7 or expired).

## A new CA

```bash
papaia-ctl pki rotate-ca
```

works in two steps, each followed by the restart of what changed:

1. A new CA is created and **added to every bundle**. Every service now trusts both.
2. The new CA becomes the active one and **every certificate is issued again** by it.
   The old CA stays in the bundle, as `retired`, until its last certificate has expired
   (the leaf lifetime plus a day); a later run removes it.

No service ever sees a peer certificate from a CA it does not trust yet.

## Bring your own CA

**An intermediate of the company PKI.** The CA that issues the leaves is then a
sub-CA of the company's root:

```bash
papaia-ctl pki rotate-ca --cert=issuing-ca.crt --key=issuing-ca.key --chain=root-and-intermediates.crt
```

The certificate must be a CA (`CA:TRUE`, `keyCertSign`) that matches the key and outlives
the leaf lifetime; an RSA key needs at least 3072 bits. When it is not self-signed,
`--chain` must hold its issuers up to the root, and the chain must verify. The root goes
into the bundle, the intermediates into every leaf. The key is copied into the CA volume
and the source files are left alone; remove them afterwards. On a fresh installation the
first `rotate-ca` with `--cert` simply makes the imported CA the active one.

**Certificates issued outside papAIa.** With `PAPAIA_PKI_MODE=external` in the root
`.env` papAIa issues nothing. The operator puts `ca-bundle.crt` into `PAPAIA_PKI_DIR` and
the requested `tls.crt`/`tls.key` and `client.crt`/`client.key` into each service
directory. Every run checks all of them (names, key usage, key match, chain against the
bundle, at least one day left) before it changes anything, names every problem at once and
stops with exit code 3 on the first set that cannot be used. A good set is then installed
like an issued one: owner, modes, `ca.crt`, `generation`, restart.

## Edge certificates stay separate

The internal CA is not the certificate a browser sees. The two live side by side:

| | Edge TLS | Internal TLS (`pki`) |
|---|---|---|
| Who connects | Users' browsers, API clients | One service to another |
| Where it ends | Nginx Proxy Manager or an external reverse proxy (Traefik, a load balancer, Cloudflare with an origin certificate) | The service itself |
| Certificates | Let's Encrypt, a company certificate, a Cloudflare origin certificate | This CA, or the company's sub-CA |
| Trusted by | Browsers and the public roots | Only the services of this installation |
| Configured with | The proxy's own settings, `--external-reverse-proxy` | `setup --pki`, `pki rotate-ca` |

Nothing of the profile touches the proxy, its certificates or the local CA that signs
Keycloak's certificate (`<PAPAIA_CONFIG_DIR>/certs/`). A Cloudflare origin certificate
is trusted by Cloudflare only and is never put into the internal bundle; the internal CA
is never offered to browsers.

The mTLS link between the nodes of a distributed installation (ADR 0010) has its own CA as
well. It authenticates nodes, not services, and stays as it is.

## Backup, restore and removal

- The CA key and the issuer's bookkeeping are in the volume `<project>_pki-ca`. It carries
  the project's label, so `papaia-ctl backup` archives it with the other volumes and
  `restore` puts it back.
- The issued files are in `PAPAIA_PKI_DIR`. Inside the config directory they are part of
  its backup; elsewhere they need not be backed up, since the next `start` issues them
  again from the restored CA.
- `papaia-ctl pki purge` (only while the profile is off) deletes the issued files;
  `--ca` deletes the CA volume as well. `papaia-ctl uninstall` deletes the files when they
  are inside the config directory, and `uninstall --clean-up` the CA volume.
- The service directories belong to the services' users. Delete them with `pki purge`,
  not with `rm` as an ordinary user.

## Distributed installations

The CA key never leaves the controller, and certificates are issued there only. Add-ons
placed on the controller are served as on a single host. An add-on placed on another node
is skipped with a warning: its certificates would have to travel with the node's bundle,
which this version does not do. Core services that opt in are served on the controller.

## Relation to the KRITIS profile

A KRITIS profile (hardened defaults for operators of critical infrastructure) is not part
of this release. When it arrives it is expected to require `pki` and to make modules such
as papaia-studio use internal TLS; the profile here is the building block for it and is
useful on its own.

## Commands and settings

| Command | |
|---|---|
| `papaia-ctl setup --pki` / `--no-pki` | Switch the profile on or off (kept on later runs) |
| `papaia-ctl pki status [--json]` | CAs and certificates with their days left; exit 1 when something needs a look |
| `papaia-ctl pki renew [--force]` | Issue what is due (or, with `--force`, everything) now |
| `papaia-ctl pki rotate-ca [--cert --key [--chain]]` | A new CA in two steps; with `--cert`/`--key` an imported one |
| `papaia-ctl pki purge [--ca] [-y]` | Delete the issued files (and the CA) once the profile is off |

| Root `.env` key | Default | |
|---|---|---|
| `PAPAIA_PKI_DIR` | `<PAPAIA_CONFIG_DIR>/pki` | Where the certificates go; written by `setup --pki`, removed by `--no-pki` |
| `PAPAIA_PKI_MODE` | `issue` | `issue`, or `external` for certificates issued outside papAIa |
| `PAPAIA_PKI_LEAF_DAYS` | `90` | Lifetime of a leaf certificate, 1 to 90 days |

The CA itself lives ten years. The issuer is the image `alpine/openssl` (see
`src/infra/pki/`), run with `docker compose run --rm`: no network, a read-only root file
system, and only the capabilities to hand files to other users.
