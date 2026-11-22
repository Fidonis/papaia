# Federation with the company directory

With a federation, persons sign in with the account of their company directory. The
bundled Keycloak brokers the sign-in to an upstream OpenID Connect provider; papaia keeps
no password of a federated person. Groups of the directory become groups (role bundles)
of the `papaia` realm through a mapping table bound to the immutable group id, and
`papaia-lifecycle` compares the account states with the directory every 60 s, so a lock
in the directory takes effect in papaia within 300 s.

The federation is optional. Without `$PAPAIA_CONFIG_DIR/security/idp.yaml` there is none,
and `papaia-ctl realm sync` removes what an earlier federation set up.

## What it needs

- the bundled Keycloak (profile `keycloak`) and `papaia-lifecycle` (profile `lifecycle`,
  see [lifecycle.md](lifecycle.md)); without the lifecycle profile `doctor identity`
  reports `fail`, because locks in the directory would not reach papaia;
- an upstream provider that speaks OpenID Connect with the authorisation code flow and
  accepts `private_key_jwt` client authentication;
- a read-only account at the directory for the status sync, with exactly two rights:
  read users and read group memberships;
- for the warning mail: the mail relay (profile `smtp`) and `PAPAIA_OPERATIONS_MAIL`
  ([configuration.md](configuration.md#federation-variable)).

The shipped status sync reads a Keycloak realm through its Admin API (`kind: keycloak`).
Microsoft Entra ID through its directory API is the target of the federation; its proof
against a real tenant is still open, see [Limits](#limits).

## The two files

Both live in `$PAPAIA_CONFIG_DIR/security/`, belong to the user running `papaia-ctl`
and must not be writable by group or others (`chmod 600`); a symbolic link is refused.
Unknown fields, a second entry for the same group id or a value of the wrong form stop
the render and the realm sync before anything is changed.

`idp.yaml` describes the provider:

```yaml
format: papaia.idp/1
issuer: https://login.example.com/realms/company
authorization_url: https://login.example.com/realms/company/protocol/openid-connect/auth
token_url: https://login.example.com/realms/company/protocol/openid-connect/token
jwks_url: https://login.example.com/realms/company/protocol/openid-connect/certs
client_id: papaia-broker
# optional: the audience of the client assertion, when the provider wants another one
# than the token endpoint (Keycloak: the issuer)
client_assertion_audience: https://login.example.com/realms/company
# the accepted `acr` values of the upstream token; any other value is refused
acr_values: ["2"]
# named in the refusal texts below
contact: "IT service desk, extension 100"
status_sync:
  kind: keycloak
  url: https://login.example.com
  realm: company
  client_id: papaia-status-sync
```

Every URL uses `https`; plain `http` is accepted on a loopback address only. No URL
carries a user, a query or a fragment, and `status_sync.url` has no path.

`idp-group-map.yaml` maps upstream groups to groups of the realm:

```yaml
format: papaia.idp-group-map/1
groups:
  - upstream_id: 3f0c2a5e-7b1d-4c8e-9a6f-2d4b8e1c7a90   # accounting
    group: buchhaltung
  - upstream_id: 8a1e4d2c-5f3b-4e7a-b9c6-1d0e2f3a4b5c   # sales
    group: vertrieb
```

`upstream_id` is always the immutable id the provider puts into the `groups` claim (for
Entra ID the object id), never a name: a group renamed in the directory stays mapped.
Each `group` must exist in the realm; a mapping to a missing group refuses the whole
federation. At most 500 entries.

## Setting it up

1. Write both files and add `lifecycle` to `COMPOSE_PROFILES`.
2. `papaia-ctl start` renders the configuration. It creates the key pair of the status
   sync account once, in
   `$PAPAIA_CONFIG_DIR/security/federation/svc-papaia-status-sync/private-key.pem`, and
   the file `status-sync.json` that `papaia-lifecycle` reads. `papaia-lifecycle` gets
   that folder read-only and reaches the host of `status_sync.url` through
   [papaia-egress](egress.md), on its port and to nothing else. The private key never
   leaves the host; print the public key for the provider with
   `openssl pkey -in private-key.pem -pubout`. Until step 3 is done, the status sync
   fails and `doctor identity` says so.
3. At the provider, register two clients:
   - the broker client `client_id`: authorisation code flow, redirect URI
     `https://<keycloak host>/realms/papaia/broker/upstream/endpoint`, client
     authentication with a signed JWT verified against the public keys of the `papaia`
     realm (`https://<keycloak host>/realms/papaia/protocol/openid-connect/certs`). Put the
     ids of the application's groups into the `groups` claim. There is no client secret;
   - the status sync client `status_sync.client_id`: client credentials only, the public
     key from step 2, and the two read rights (Keycloak: `realm-management` roles
     `view-users` and `query-groups`, nothing else).
4. `papaia-ctl realm sync` sets up the realm (one `papaia.audit/1` row per change):
   - the identity provider `upstream`: authorisation code with PKCE S256, client
     authentication `private_key_jwt`, signatures checked against `jwks_url`, the e-mail
     address of the provider never trusted, its tokens not stored, sync mode `FORCE`
     (every sign-in applies the mapping anew, so a group removed upstream is gone at the
     next sign-in);
   - the first sign-in flow `papaia-federation-first-login`: an account is created when
     no account of that name or address exists, otherwise the sign-in fails. An account
     is linked by the provider's `sub` only, never by name or address;
   - the post sign-in flow `papaia-federation-check` (see below);
   - one mapper per entry of the group map;
   - the sign-in page of the realm leads to the provider without a choice;
   - the realm stores refused federated sign-ins (user event
     `IDENTITY_PROVIDER_POST_LOGIN_ERROR`).

`papaia-ctl realm sync --check` reports deviations without changing anything.

## Signing in

A federated person signs in at the provider; papaia holds no local password for them.
The only local accounts are the break-glass account and service accounts. They sign in
with `kc_idp_hint` set to an alias that does not exist, for example
`.../protocol/openid-connect/auth?...&kc_idp_hint=local`, which shows the local form.

The post sign-in flow refuses a sign-in, fail-closed:

- without a `groups` claim, or with an overage reference (`_claim_names.groups`, what
  Entra ID sends instead of the claim above 200 groups); the person keeps their bundles,
  nothing is removed silently. Text shown:

  > Anmeldung nicht möglich: Ihr Konto gehört im Firmenverzeichnis zu mehr Gruppen, als
  > die Anmeldung übermitteln kann. Deshalb lassen sich Ihre Berechtigungen nicht sicher
  > bestimmen, und Sie werden nicht angemeldet. Wenden Sie sich an {contact}; dort kann die
  > Gruppenauswahl für papaia eingeschränkt werden.

- with an `acr` outside `acr_values`. Text shown:

  > Anmeldung nicht möglich: Ihre Anmeldung beim Firmenverzeichnis erfüllt nicht die
  > verlangte Anmeldestärke (zum Beispiel ein zweiter Faktor). Melden Sie sich erneut an
  > oder wenden Sie sich an {contact}.

Issue only the groups assigned to the application in the directory, or use app roles,
so the claim stays below the provider's limit.

`papaia-lifecycle` reads the refused sign-ins from the realm's user events and writes
one audit row per attempt: `idp_group_overflow` for the first case, a denied
`sign_in` row with `idp_acr_refused` for the second.

## The status sync

Every 60 s `papaia-lifecycle` reads the directory with the status sync account: the list
of users (state and "sessions valid from") and the members of every mapped group, as
lists, with no request per account. The link between an account of the realm and its
person upstream is Keycloak's federated identity (the provider's `sub`), read once per
account and kept; accounts that are not federated are looked at again once a day. Each
finding is handled like the local case of [lifecycle.md](lifecycle.md):

| Upstream | In papaia |
|---|---|
| person locked or deleted | account disabled, put on the revocation list (`upstream_disabled`, `upstream_deleted`), sessions ended, every consent removed |
| person enabled again | account enabled, if the status sync disabled it; consents from before the lock are removed, so no old delegation comes back |
| "sessions valid from" moved forward (sessions revoked, no lock) | revocation list (`upstream_sessions_revoked`), sessions ended, consents removed; the account stays enabled |
| membership of a mapped group changed | sessions ended (`role_changed`), so the next sign-in maps anew; a removal is written to the erasure journal |
| group renamed | nothing: the mapping binds to the id |

An account deactivated in papaia itself (in the Manager, for example) stays deactivated:
the status sync enables only accounts it disabled, so the directory cannot lift a lock
set in papaia. Every write is one `papaia.audit/1` row with one correlation id per
account and round.
A lock made while `papaia-lifecycle` was stopped is found by the first round after its
start.

A round that fails (the directory does not answer, refuses the account, throttles, or
answers something unusable) changes nothing more; what it already did for the accounts it
finished is kept, so the next round does not repeat it. When the status sync has failed for longer
than 300 s, `papaia-lifecycle` writes one `status_sync_failed` row, sends one warning mail
to `PAPAIA_OPERATIONS_MAIL` (an `alert_mail` row, sent or not) and its health becomes
`fail`; `papaia-ctl doctor identity` then reports `fail` ("federation disturbed"). The
first successful round clears it; a later failure is reported again after 300 s.

## When the provider is down

Existing sessions stay valid up to their end; a new sign-in shows Keycloak's error page;
the break-glass account still signs in (`kc_idp_hint`, above). Locks in the directory do
not reach papaia while the status sync fails, which `doctor identity` reports.

## Removing it

Delete `security/idp.yaml` and `security/idp-group-map.yaml`, then `papaia-ctl realm
sync` and `papaia-ctl start`: the identity provider, its flows and marker roles and the
redirect of the sign-in page are removed, and `papaia-lifecycle` runs without the status
sync and drops its state, so its health no longer counts it. Accounts created by federated sign-ins stay; disable or delete them as usual. The
key of the status sync account stays until you delete its folder, so remove the client
at the provider too.

## Limits

- The status sync of this release reads a Keycloak realm (`kind: keycloak`). Entra ID
  (delta queries with throttling, the `tid`/`oid` pair, the two application permissions
  and their consent, group overage) is the target and not yet proven against a real
  tenant.
- The group limit is the provider's: papaia refuses the overage reference and a missing
  claim, it does not count the entries of the claim.
- LDAP or Active Directory directly is not tested.
- A switch "block new sign-ins while the status sync fails" is not part of this release.
- `papaia-ctl status` does not show the federation; use `papaia-ctl doctor identity`.
