# Validating a two-node installation

The distributed mode rests on assumptions that only real machines can confirm: certificate
trust across the boundary, OIDC discovery through the link, streaming through the gateway,
the firewall rules it needs. This runbook is the hand-run check for them. Run it on two
fresh Linux VMs with a firewall between them. Touch no existing installation and use a
throwaway config directory. Record the result with the report template at the end.

## Setup

| Machine | Role | Runs |
|---|---|---|
| **A** (edge, DMZ) | `edge` | Nginx Proxy Manager, Keycloak (+ Postgres), LiteLLM (+ database), SMTP relay |
| **B** (internal) | `internal`, controller | everything else, papaia-manager among it |

1. On both VMs: Docker with the compose plugin, Python 3.10+ with PyYAML, an SSH server.
   Between them a firewall that drops everything not opened below.
2. On B, in a fresh checkout and with a throwaway config directory:

   ```sh
   tools/papaia-ctl setup --config-dir=/tmp/papaia-validate --topology=distributed \
       --node internal=<B address> --node edge=<A address>,ssh=papaia@<A address> \
       --preset=dmz-split --app-host=https://papaia.<test domain> -y
   tools/papaia-ctl topology firewall --config-dir=/tmp/papaia-validate
   ```

3. Open exactly the rules `topology firewall` prints (plus 80/443 from the clients to A).
4. Enrol A with the join archive (`node add edge ... --bootstrap=join`, then
   `sudo ./install.sh` on A, then `node check edge`), and start:
   `tools/papaia-ctl start --config-dir=/tmp/papaia-validate`.

## Checks

Mark each one **confirmed**, **refuted** or **blocker**, with a line of evidence (a command
and its output, a log excerpt).

- [ ] **Sign-in across the boundary.** LibreChat on B signs in against Keycloak on A. That
      includes LibreChat's server-side OIDC discovery against the public auth URL. It
      should go through the gateway alias for the auth host (`docker exec` into LibreChat on
      B, `getent hosts auth.<domain>` resolves to the gateway; the discovery document loads
      with the real certificate). If it does not, record the fallback that works: split DNS
      plus a 443 rule from B to A.
- [ ] **Local CA next to a public certificate.** `SSL_CERT_FILE=/certs/local-ca.crt` on
      oauth2-proxy, LocalAI, papaia-manager, qdrant-mcp and the ingester still verifies the
      public certificate of the auth host. If it does not, this is a single-host problem too;
      note it as such.
- [ ] **Chat through LiteLLM on A.** A chat completes from LibreChat on B through LiteLLM on
      A to a provider and back, with SSE streaming. Also run one long answer of several
      minutes; it must not be cut by an idle timeout (the gateway's `timeout tunnel` is 1 h).
- [ ] **Ingress to B.** Nginx Proxy Manager on A proxies `librechat:3080` on B, WebSocket
      included (the LibreChat UI streams; the browser's network tab shows the upgrade).
- [ ] **Keycloak's own certificate.** `https://keycloak:8443` still validates through the
      gateway (SAN `keycloak`). papaia-manager's Users & Roles page (Keycloak) and Models &
      Usage page (LiteLLM) work on B.
- [ ] **Aliases and SNI.** A Docker network alias with a full host name resolves inside the
      containers. Routing by SNI after mTLS termination works with several services behind
      the one link port (`docker logs <project>-link-gateway-1` on A shows the routed
      sessions).
- [ ] **Ports.** The published ports do not collide on the owning node (3080, 8000, 8080,
      6333, 4000, 8443, 8300) or with the link port. `papaia-ctl doctor` passes `ports` on
      both nodes.
- [ ] **Token issuer in the manager.** Confirm that papaia-manager decodes tokens without
      checking the issuer (`jwt.decode` without `issuer=`) and note it.
- [ ] **External OIDC endpoints.** With `AUTH_PROVIDER=external_oidc`, a setup run sets only
      part of the OIDC endpoints for oauth2-proxy and the manager. Note what it actually
      writes.
- [ ] **Realm JSON with secrets.** Check whether `infra/keycloak/realm-import/papaia-realm.json`
      on A can be removed after the first import, or re-rendered without secrets.
- [ ] **One privileged step.** The join archive installs on A with a single `sudo ./install.sh`
      (checkout, user, `authorized_keys` line), and nothing else needs root afterwards.
- [ ] **Firewall rules.** The rules the installation really needs match
      `topology firewall`: SSH and the link port from internal to edge, the link port from edge
      to internal. Close any one of them and observe what breaks (`doctor` should name it
      under `links`).
- [ ] **Clock skew.** Moving A's clock by a few minutes breaks token validation as expected,
      and `doctor` reports the deviation under `nodes`.

## Report

Post it as a comment on the validation issue.

```markdown
## Two-node validation — <date>

**Decision:** go | no-go

| Check | Result | Evidence |
|---|---|---|
| Sign-in across the boundary | confirmed / refuted / blocker | ... |
| ... | | |

**Confirmed assumptions:** ...
**Refuted assumptions:** ...
**Blockers:** ...
**Effort estimate for the follow-ups:** ...
```
