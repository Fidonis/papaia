# Sign-in addresses of add-on clients

An add-on whose clients sign persons in needs their redirect URIs, and often a post-logout
redirect, a back-channel logout URL and a web origin, in the realm. Since add-on contract
generation 18 the add-on declares them in its manifest and `papaia-ctl realm sync` sets
them; nobody enters them by hand, and the add-on never holds a realm token
([ADR 0028](adr/0028-set-the-sign-in-addresses-of-add-on-clients-from-the-manifest.md)).

## The key

```yaml
name: papaia-flow
requires:
  addon_api: [18]
integration:
  nginx:
    - {host_key: console, service: flow-console, port: 8080}
client_addresses:
  - client: flow-console                        # a confidential client this add-on owns
    host_key: console                           # one of the integration.nginx entries above
    redirects: [/auth/callback]                 # 1 to 8 exact paths
    post_logout: [/]                            # optional, up to 8 exact paths
    backchannel_logout: /auth/backchannel-logout  # optional, one exact path
    web_origin: true                            # optional, default false
  - client: flow-engine
    host_key: console
    redirects: [/engine/test-run/callback]
```

| Field | Meaning |
|---|---|
| `client` | A client of the names register whose owner is this add-on (the manifest `name`) and that signs persons in with credentials (confidential). |
| `host_key` | One of the add-on's own `integration.nginx` entries. The core gives it its host name; the manifest never names a host. |
| `redirects` | The redirect URIs, as paths on that host. |
| `post_logout` | The post-logout redirects. Without the field: none. |
| `backchannel_logout` | The back-channel logout URL. Without the field: none. |
| `web_origin` | `true`: the host is the client's web origin (for requests from the browser). Without the field or `false`: no web origin. |

At most 8 entries, one per client.

## What the realm gets

`realm sync` puts the public URL of the interface in front of every path: the scheme, host
name and port of the edge, as `papaia-ctl proxy list` shows them. With `PAPAIA_HOST` set to
`https://papaia.example.org` the console above signs in at
`https://console.papaia.example.org/auth/callback`; on a local installation at
`https://console.<env>.papaia.localhost:<edge port>/auth/callback`; renamed with
`INGRESS_HOST_CONSOLE`, under the new name.

The client gets exactly these addresses and the attribute
`papaia.sign-in-addresses=declared`. Realm hardening keeps them and removes every other
redirect URI, web origin, post-logout redirect and back-channel URL of the client. A second
run changes nothing; `realm sync --check` reports an address someone changed by hand as
`fail`, the next sync puts it back. Each change is one audit row.

| Change | Result |
|---|---|
| A path removed from the manifest | Removed from the client at the next sync |
| An entry or the whole key removed | Every address of the client removed |
| `addon remove`, the add-on disabled | The client stays, without any address |
| `addon uninstall` | The client is deleted with its addresses |
| No proxy (`REVERSE_PROXY_PROVIDER=no_proxy`) | No host names, so no address; the sync notes it |
| A client without a declaration | Left as it is |

## Paths

Every path is absolute and exact:

- starts with `/`;
- no wildcard `*`, no query `?`, no fragment `#`;
- no `..` or `.` segment and no `//`;
- only `A-Z a-z 0-9 . _ ~ -` and `/`, no percent-encoding;
- at most 255 characters.

## Refusals

`papaia-ctl addon check` and every add-on command that runs the compatibility gate report
these as a malformed manifest, naming the entry (`client_addresses[1] (flow-console): ...`);
neither `--force` nor warn mode lets them in. `realm sync` refuses the same declaration
before it changes anything (exit 2).

- a client that is not registered, or that belongs to another add-on;
- a client of the core (`librechat`, `papaia-audit`, `papaia-manager`, `oauth2-proxy`, the
  clients of core profiles such as `papaia-me`): their addresses come from the core's own
  settings;
- a public client (`flow-cli`), a bearer-only client (`flow`) or the exchange-only chain
  holder (`papaia-data`);
- a `host_key` that is not one of the add-on's `integration.nginx` entries (the list form;
  the old fragment-path form has none);
- a path outside the rules above, an empty `redirects`, more than 8 redirects or
  post-logout paths, a path listed twice, an unknown or missing field, a client listed twice;
- under the `kritis` security profile, an edge that is plain http.

## Older cores

`client_addresses` is a generation-18 key. A core whose window ends below 18 reports the
add-on `INCOMPATIBLE` with `missing generation 18` and the key. A core from before this
generation does not know the key at all; forced there, it installs the add-on without
addresses, and nobody can sign in at its clients until an administrator enters them. Name
`requires.addon_api: [18]` to make such a core refuse the add-on.
