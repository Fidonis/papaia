# Isolated add-on networks

A service that hands foreign content (a mail, a document, a web page) to a model should
share a network with nothing but the model gateway. An add-on declares such a network with
`networks.isolated` (add-on contract generation 16,
[ADR 0026](adr/0026-isolated-add-on-networks-that-reach-only-the-model-gateway.md)); the
core puts LiteLLM on it and nothing else.

## Declaring an isolated network (add-on authors)

The add-on's own compose file creates the network with `internal: true` and puts only the
service that reads foreign content on it:

```yaml
# docker-compose.yml of the add-on
services:
  reader:
    image: ...
    networks: [reader]        # this network only
  app:
    image: ...
    networks: [app]
networks:
  app:
    name: ${PAPAIA_PROJECT:-papaia}-<name>-net
  reader:
    name: ${PAPAIA_PROJECT:-papaia}-<name>-reader-net
    internal: true
```

The manifest declares it next to `app_network`:

```yaml
# papaia-app.yaml
requires:
  addon_api: [16]
networks:
  app_network: ${PAPAIA_PROJECT:-papaia}-<name>-net
  attach: [nginx-proxy-manager, keycloak, papaia-audit]
  isolated:
    - network: ${PAPAIA_PROJECT:-papaia}-<name>-reader-net
      attach: [litellm]
```

`papaia-ctl` writes `$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml` with
`litellm` on the isolated network (next to the networks it already has) and every service of
`attach` on `app_network`, as before. The ingress proxy of `integration.nginx`, the egress
attachment and all other automatic attachments stay where they were. The service `reader`
reaches `http://litellm:4000` and nothing else: no core service, no service of the add-on on
`app_network`, no address outside the host, because an internal network has no route out.

Up to eight isolated networks per add-on are allowed; each is rendered on its own.

## What the core refuses

`papaia-ctl addon check`, `addon install`, `addon start`, `addon upgrade` and
`addon rollback` refuse the add-on, naming the entry (`networks.isolated[<i>]`), when

- an entry has a field other than `network` and `attach`;
- `attach` is missing or empty, names a service twice, or names a service other than
  `litellm` (for example `keycloak`, `nginx-proxy-manager`, or a service no add-on may attach
  such as `papaia-audit-db`);
- `network` is not scoped to the add-on: `${PAPAIA_PROJECT:-papaia}-<name>-...` or its
  literal default `papaia-<name>-...`;
- `network` is the add-on's `app_network`, its egress network (`networks.egress.network`),
  the network of another entry, a core network or one of Docker's networks (`bridge`,
  `host`, `none`);
- the add-on's `docker-compose.yml` does not create the network under that `name:` with
  `internal: true` (a network declared `external` is refused too).

These are malformed manifests: neither `--force` nor warn mode lets them through. The render
of the overrides applies the same checks and also stops when another add-on in
`deployment.yaml` declares the same network.

A core whose contract window ends below 16 reports the add-on `INCOMPATIBLE` with the
missing generation named, instead of starting it without LiteLLM on the network:

```text
reason: addon uses `networks.isolated` (addon_api 16); core serves addon_api [1..15];
missing generation 16; 16: `networks.isolated`: internal add-on networks only `litellm`
joins (ADR 0026)
```

## Why only LiteLLM

The allow-list is one constant, `ISOLATED_ATTACHABLE` in `tools/lib/compat.py`, pinned by
the contract snapshot. A process that reads foreign content may be steered by what it
reads; its only peer is the model, and the module's model key carries only the models the
module needs ([model gateway](model-gateway.md)). Another service joins the list only with a
new contract generation and a new decision record.
