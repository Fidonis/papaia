# papAIa Documentation

Welcome to the papAIa documentation.

## Contents

- [Architecture](./architecture.md) — system overview, services, data flows
- [Configuration](./configuration.md) — environment variables and configuration files
- [Deployment](./deployment.md) — local and remote deployment paths
- [Troubleshooting](./troubleshooting.md) — common issues and fixes
- [Running on several machines](./distributed.md) — the operator guide of a distributed
  installation
- [Validating a two-node installation](./distributed-validation.md) — the hand-run check of
  the distributed mode on two machines
- [The single exit](./egress.md) — papaia-egress: allow lists per add-on, protected hosts,
  corporate proxy
- [Isolated add-on networks](./isolated-networks.md) — `networks.isolated`: an internal
  network of an add-on whose only core peer is the model gateway LiteLLM, and what the core
  refuses
- [Offered add-on networks](./offered-networks.md) — `networks.join_addons[].network`: join
  the network another add-on offers through an `exposes` entry instead of its app network
- [Sign-in addresses of add-on clients](./client-addresses.md) — `client_addresses`: the
  redirect URIs, logout addresses and web origin of an add-on's clients, set by the realm sync
- [Network routes](./network.md) — the communication matrix, the direct route of the SQL
  source (`papaia-sql-uplink`, host rules, `doctor network`) and `topology firewall`
- [Account lifecycle and revocation](./lifecycle.md) — papaia-lifecycle: revocation on
  deactivation, reconciliation independent of events, the signed revocation list, the
  erasure journal `identity`, its service account
- [Deletions for the core start gate](./replay.md) — papaia-replay: deletes a person in
  chat and model gateway, chat sessions and gateway keys for the start gate, over mutual
  TLS, with a fixed chat role, counts only
- [Federation with the company directory](./federation.md) — sign-in through an upstream
  OpenID Connect provider, groups mapped by immutable id, the status sync of locks
- [Model gateway](./model-gateway.md) — LiteLLM for the modules: aliases, the default model,
  one key per module, no stored contents
- [Platform halt](./halt.md) — `papaia-ctl halt`: stop every write, send and delete of the
  installation with one host command
- [The Docker socket broker](./docker-gate.md) — papaia-docker-gate: the manager's only way to
  Docker, status and start/stop of the installation's containers
- [The audit store](./audit.md) — papaia-audit: ingest over mutual TLS, hash chain per source,
  verification and signed chain heads, the read API with pseudonyms and the person filter
  that needs a reason and a second person
- [People lookup](./people.md) — papaia-people: exact-match lookup of persons with an
  assistant role for `assist-gate`, the bounded group member lookup for Studio's share
  notices, its service account and audience
- [Platform PKI and trust bundle](./pki.md) — certificates for TLS between services, their
  renewal, company CA certificates, the security profile `kritis`
- [Information and erasure without an account](./person-requests.md) — `papaia-ctl person
  export|erase`: the person actions of the modules, the encrypted archive, the erasure journal
  check and the proof per module and category
- [Hosted test model](./hosted-test-model.md) — a model outside the stack, in the test stack
  only
- [Wiederherstellung](./de/wiederherstellung.md) — the operator steps of a restore, in
  German, like the data protection package under `de/`
- [Architecture Decision Records (ADRs)](./adr/) — recorded architecture decisions
- [Parallel Search MCP in LibreChat](./parallel-search-mcp.md) — opt-in hosted web search
  through the customer overlay

### Delivery documents in German

- [Datenschutzunterlagen](./de/datenschutz/index.md) — records of processing, logging, why no
  performance or behaviour control is offered, input for a data protection impact assessment,
  technical and organisational measures, points for a works agreement
- [Lizenz und Bezug](./de/betrieb/lizenz-und-bezug.md) — license, cost and contract per
  component, image sourcing and availability, exit, support and security fixes
- [Auskunft und Löschung ohne Konto](./de/betrieb/auskunft-und-loeschung.md) — the operator
  steps for a person whose account is gone, and what an erasure means for the backups
- [Nachweis mit dem ausgelieferten Modell](./de/betrieb/modellnachweis.md) — how the modules are
  checked with the smallest shipped model and what the report holds
- [Anmeldung, Abmeldung und Einstiegsseite](./de/betrieb/anmeldung-und-einstieg.md) — the
  entry page behind the main address, the shared login page and the sign-out in every module
- [Studio-Apps und der Rand des Stapels](./de/betrieb/app-hosts-am-rand.md) — what the
  edge does for Studio app hosts, how `doctor edge_app_origin` checks it, and what to do
  about a finding (German operator text)

## Conventions

- All documentation is written in **English**, except the delivery documents for operators,
  data protection officers and works councils under [`de/`](./de/), which are German.
- Markdown is the primary format.
- Code samples use fenced blocks with a language tag for syntax highlighting.

## Contributing to the docs

See the root [`CONTRIBUTING.md`](../CONTRIBUTING.md) for general guidelines. For documentation-specific issues you can also use the [Documentation issue template](https://github.com/Fidonis/papaia/issues/new?template=documentation.yml).
