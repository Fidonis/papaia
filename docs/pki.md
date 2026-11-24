# Platform PKI and trust bundle

Every installation has one certificate authority for TLS between its own services, the
**platform CA**. Modules and core services get their certificates from it, in one layout
(contract `papaia.platform-pki/1`), and trust one bundle. Company root certificates are
added to that bundle in one place. The decision behind it is
[ADR 0019](adr/0019-issue-internal-tls-from-one-platform-ca.md); what the security profile
asks of it is [ADR 0022](adr/0022-one-security-profile-for-the-whole-installation.md).

- [When TLS between containers is required](#when-tls-between-containers-is-required)
- [TLS to the module services](#tls-to-the-module-services)
- [Asking for certificates](#asking-for-certificates)
- [What a service gets](#what-a-service-gets)
- [The CA key](#the-ca-key)
- [Lifetimes and renewal](#lifetimes-and-renewal)
- [A new CA](#a-new-ca)
- [Company CA certificates](#company-ca-certificates)
- [Checking the certificates](#checking-the-certificates)
- [Commands and files](#commands-and-files)

## When TLS between containers is required

The security profile `PAPAIA_SECURITY_PROFILE` decides
([configuration.md](configuration.md#what-each-security-profile-means)):

- `standard`: TLS ends at the reverse proxy. The audit ingest (`papaia-audit:8443`) uses
  mutual TLS with its own CA (see below). The platform certificates are issued for every
  request.
- `kritis`: the same, and an add-on must request certificates: an add-on without a `pki:`
  request is refused by `papaia-ctl addon install`, and `papaia-ctl start` stops before
  anything starts while such an add-on is active. The core reaches the module services
  over TLS ([below](#tls-to-the-module-services)). Whether another add-on uses its
  certificates on its own links is up to the add-on.

Apart from the module services, the links between core containers do not use TLS yet in
either profile. papaia-lifecycle
gets its certificates (`src/infra/lifecycle/pki.yaml`), but its compose file does not
mount them and its calls do not present a client certificate; wiring the core links to
the platform PKI is a later step.

The certificates are issued in both profiles; the edge certificates of the reverse proxy,
the Keycloak CA (`<config>/certs/local-ca.crt`) and the link CA of distributed
installations stay as they are. So does the ingest CA of the audit store
([audit.md](audit.md)): mutual TLS at `papaia-audit:8443` accepts only client certificates
of that CA whose fingerprint is listed for their source (`papaia-ctl audit cert <source>`),
so a certificate of the platform PKI is not an audit source.

## TLS to the module services

Under `kritis` the core points at Flow (`papaia-flow`), the assistant (`papaia-assist`),
Me (`me-web`) and the connection registry (`connections`) only over TLS of the platform
CA (`tools/lib/module_tls.py`):

- **Proxy.** The proxy host of each of their interfaces (`integration.nginx`, and
  `ME_PUBLIC_URL` for `me-web`) forwards with https. The proxy checks the certificate
  against the platform CA under the service's name (`proxy_ssl_verify on`,
  `proxy_ssl_name`), speaks TLS 1.3 and presents its own client certificate
  (`src/infra/nginx/pki.yaml`). `papaia-ctl npm-provision` corrects a host that still
  forwards in plain HTTP. `papaia-ctl proxy list` marks these forwards `tls-platform-ca`.
  The host of the main address, which redirects every request to Mein Bereich, names
  `me-web` with the same https upstream.
- **Sign-out.** Keycloak does not trust the platform CA, so it no longer calls Me's
  back-channel logout on the stack network (`http://me-web:8000`). The realm sync sets it
  to `ME_PUBLIC_URL` + `/auth/backchannel-logout`, through the proxy, as for the add-ons
  (`tools/lib/sign_in.py`; with a local `.localhost` name the call fails and Me learns of
  the sign-out at the next token refresh).
- **Catalog.** Their addresses in `platform/services.json` are https, under a name their
  server certificate covers (the service, its container name or a network alias of the
  service, in that order). Me calls the assistant at that address and checks it against
  the platform CA.
- **me-web.** The override `overrides/docker-compose.module-tls.override.yml` mounts
  `<config>/pki/core/me-web/` into `me-web`, which then listens with its server
  certificate (`src/infra/me/pki.yaml`) and checks the modules it calls against the
  platform CA. The same override mounts `<config>/pki/core/nginx-proxy-manager/` into the
  proxy. Under `standard` the override is removed.

A module service without a server certificate for the name it is reached under stops the
render: `papaia-ctl proxy list`, `npm-provision`, `catalog render` and every `setup`,
`start` and `addon` step name the service and refuse the plain upstream. It is never
forwarded in plain text. The module must then add the name to `server.dns` of its `pki:`
request. Other add-ons keep plain HTTP behind the proxy under both profiles.

## Asking for certificates

An add-on asks in its manifest, `papaia-app.yaml` (contract generation 11, so it lists
`11` in `requires.addon_api`):

```yaml
pki:
  services:
    - name: studio-gateway        # a DNS label; the CN of the client certificate
      uid: 10001                  # numeric user of the container that reads the files
      server:
        dns: [studio-gateway]     # names the service is reached under
      client: true                # also a client certificate
    - name: studio-db
      uid: 999
      server:
        dns: [studio-db]
    - name: studio-worker
      uid: 10001
      client: true                # client only
```

Each entry needs a server certificate, a client certificate or both. Unknown keys, a
name that is not a DNS label, a server name that is not a DNS name (no wildcards) and a
name requested twice are refused. `uid` may be left out: the files then belong to the
user that runs `papaia-ctl`.

A core service asks in a `pki.yaml` next to its compose file, with the profile it
belongs to; its files land under the module name `core`:

```yaml
profile: lifecycle
pki:
  services:
    - name: papaia-lifecycle
      server: {dns: [papaia-lifecycle]}
      client: true
```

The release ships one: `src/infra/lifecycle/pki.yaml`.

## What a service gets

```
$PAPAIA_PKI_DIR = <config>/pki/
  ca/                          0700  the CA, read by papaia-ctl only
  ca-bundle.crt                0644  every CA the services trust
  inventory.json               0644  what is issued, with end dates
  <module>/<service>/          0700  owned by the service's uid
    ca.crt                     0644  the bundle
    tls.crt, tls.key           0644 / 0600  server certificate (when `server` is requested)
    client.crt, client.key     0644 / 0600  client certificate (when `client: true`)
    generation                       raised whenever something here changed
    request.json                     what was requested
```

- Server certificates carry `extendedKeyUsage serverAuth` and the requested names; client
  certificates carry `clientAuth` and `CN=<service name>`. The peer authorizes by that name.
- Keys are ECDSA P-256. A key is replaced before its certificate and `generation` is
  written last: a service that sees a new `generation` sees a complete set.
- A compose file mounts only its own directory, read-only, for example
  `${PAPAIA_PKI_DIR}/studio/studio-gateway:/run/secrets/tls:ro`. Ownership is handed to
  `uid` when `papaia-ctl` runs as root; otherwise `papaia-ctl` warns on Linux when the
  service runs as another user.

## The CA key

The key of the platform CA is `<config>/pki/ca/ca.key`, mode 0600 in a 0700 directory,
owned by the user that runs `papaia-ctl`. No container mounts it, and the service
directories never contain it. It is part of the configuration backup like the Keycloak CA.
Whoever can read the configuration directory as that user or as root can sign
certificates; papaia-manager runs `papaia-ctl` and can, which is the same boundary as for
the other keys there.

## Lifetimes and renewal

| Certificate | Lifetime | Renewed |
|---|---|---|
| Platform CA | 10 years | a year before its end, or with `certs renew --ca` |
| Server and client certificates | 90 days | with 30 days left, at once when the request or the CA changed |

`papaia-ctl setup`, `papaia-ctl start` and `papaia-ctl addon start` issue what is
missing, renew what is due and remove the directory of a service that is no longer
requested. A run with nothing to do changes nothing. Every issue, renewal, removal, new CA
and import is one `papaia.audit/1` row in the audit outbox
(`<config>/audit/outbox/papaia-ctl.jsonl`) with one correlation id per run; no key or
certificate content is written there.

On a host that is not restarted for weeks, renew from a daily timer:

```bash
papaia-ctl certs renew            # what is due
papaia-ctl certs renew --force    # every certificate again, same CA
```

A running service reads the new files when it watches `generation`, otherwise at its next
start.

## A new CA

```bash
papaia-ctl certs renew --ca
```

makes a new CA and issues every certificate again. The old CA stays in every `ca.crt` and
in the trust bundle for 90 days, until the last certificate it signed has ended, so peers
that still hold an old certificate keep being accepted. No reinstallation, no data is
lost.

The new key and certificate are written next to the old pair and moved into place only
once both exist; a run that fails halfway leaves the old CA as it was. If the CA key no
longer matches the CA certificate (a file replaced by hand), the next run makes a new CA,
keeps the old certificate in the bundles for 90 days and issues every certificate again;
it says so and writes an audit row (`pki.ca_repair`).

Only one run writes at a time: `setup`, `start`, `addon start`, `certs renew` and the
bundle import take an exclusive lock on `<config>/pki/.lock` and wait up to two minutes
for another run to end.

## Company CA certificates

Mail server, SQL Server, registry mirror or an upstream identity provider may carry
certificates of a company PKI. Their root certificates go in **one** place:
`<config>/certs/trust/ca-bundle.pem`. It holds the platform CA and the company roots. A
service that connects to such a system mounts this file read-only and points
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` or `NODE_EXTRA_CA_CERTS` at it (Keycloak: its
truststore path); no service keeps a second list. No core service mounts the file yet:
Keycloak's truststore and the mail sender still use their own defaults, so a company
root does not reach them in this release.

Give the roots to setup, as a PEM file with one or more certificates:

```bash
papaia-ctl setup --ca-bundle=/path/to/company-roots.pem
```

or answer the setup question *Company CA certificates* (empty: none). The file is checked
at once: only CA certificates (`CA:TRUE` in Basic Constraints), none expired, no private
key, at most 1 MiB. An unusable
answer is asked for once more; a second one stops setup without a change. With the flag, an
unusable file stops setup before anything is written. The imported roots are kept in
`<config>/certs/trust/company.pem`; a later `--ca-bundle` replaces them.

## Checking the certificates

```bash
papaia-ctl certs status           # every certificate with its end and days left
papaia-ctl doctor                 # check `certs`
```

`doctor`'s `certs` check covers the Keycloak certificates, the Let's Encrypt certificates
of the Nginx Proxy Manager, the platform CA, every service certificate and the trust
bundle: a warning under 30 days left, a failure under 7 days or when one has expired.

## Commands and files

| Command | Effect |
|---|---|
| `papaia-ctl setup --ca-bundle=FILE` | Check and import company root certificates |
| `papaia-ctl certs renew [--force] [--ca]` | Issue and renew; `--force` every leaf; `--ca` a new CA |
| `papaia-ctl certs status [--json]` | List the certificates with their end dates |
| `papaia-ctl doctor` | Check `certs` includes the platform PKI |

| Path | Content |
|---|---|
| `<config>/pki/` (`PAPAIA_PKI_DIR`) | CA, bundle, inventory, one directory per service |
| `<config>/pki/.lock` | Held by the run that writes the PKI |
| `<config>/certs/trust/ca-bundle.pem` | The one trust bundle: platform CA and company roots |
| `<config>/certs/trust/company.pem` | The imported company roots |
