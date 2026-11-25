# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release notes are generated automatically by [release-drafter](https://github.com/release-drafter/release-drafter)
based on merged pull requests; this file mirrors the published releases.

## [Unreleased]

<!-- Updated automatically by release-drafter as PRs are merged to `main`. -->

### Core test suite in parallel shards

- The CI job "Ruff and pytest" ran the whole core suite in one job and hit its 20-minute
  limit on every run since 24 November 2026. The suite now runs as parallel shards
  (`tools/tests/shards.toml`, one job `pytest (<shard>)` each, with a timeout of about
  twice its measured duration and at most 30 minutes); ruff runs once in the job "Ruff".
  "Ruff and pytest" is now the aggregate check and passes only when ruff, the shard check
  and every shard passed, so the branch protection keeps its required check.
- New job "Test shards cover the suite": collects the whole suite and fails when a test is
  in no shard or in two or a shard names a missing file (`tools/tests/shard_check.py`).
- The install steps for Compose, HAProxy and gitleaks moved into the shared action
  `.github/actions/test-tools`, with their checksum checks; each shard installs only what
  its files need.
- Docker live tests take their Compose project names and subnets per session
  (`tools/tests/live_names.py`) instead of fixed defaults, so two runs on one Docker host
  no longer collide; the per-test overrides still apply.
- The secret scan tests planted random values that gitleaks drops about once in 60 runs
  (stop words inside the value, low entropy); the values stay random but are now always
  found.

### Fixed krb5 in the audit image

- `papaia-audit` carries `krb5-libs` `1.22.3-r0` on linux/amd64 and linux/arm64
  (CVE-2026-107364, CVE-2026-112315 to CVE-2026-112323, CVE-2026-118380,
  CVE-2026-119079, CVE-2026-40355, CVE-2026-40356, CVE-2026-71199, CVE-2026-71200).
  A stage on the build platform fetches exactly this version from the Alpine
  repositories of the base and the final stage only copies the result; the base
  digest is unchanged. The image is rebuilt and re-pinned.
- A registry that refuses a request, including the token request of an anonymous
  pull, is reported with the refused URL at the pin's file and line by
  `tools/check-image-pins` instead of stopping the check with a bare HTTP error.

### Image scan: findings with a fix block, findings without a fix are reported

- The gate of the core's own images (`tools/scan-images`, workflow "Core images") now
  decides from the fix state of each finding: a CRITICAL or HIGH finding with a fix
  fails, one without a fix passes and is listed in `no-fix.txt` of the `images-report`
  artefact (90 days) and counted per image in the step summary. Before, every CRITICAL
  finding and every HIGH finding without an entry failed, also when no fix existed.
- `security/exceptions.yaml` keeps the rules for the own images (HIGH only, at most 90
  days, countersigned). A third-party image may carry an entry for a finding with a
  fix only when it names the pinned digest and ends at most 14 days after `added`. An
  entry that only covers findings without a fix, an expired entry and a pending
  countersignature fail or waive nothing.
- New self test "Seeded finding without a fix passes"; the seeded fixable fixture now
  holds a critical and a high finding. `docs/compatibility.md` documents the rule, the
  report and the monthly review ("Image scan rule").

### papaia-ctl runs from its own runtime environment

- `papaia-ctl` failed on a host with exactly the documented prerequisites: every `lib.cli`
  command imports the kit (`papaia_kit.erasure`, the erasure journal mirror), which was a
  development dependency only and needs Python 3.12. The kit is now a runtime dependency
  (`tools/pyproject.toml`: `requires-python = ">=3.12"`), and `tools/runtime.lock` pins the
  runtime set (PyYAML, the kit and the kit's dependencies) by hash, exported from
  `tools/uv.lock`; a test keeps it in step with `uv.lock` and `kit.lock`.
- `setup`, `upgrade` and `rollback` build the environment `tools/.runtime/<sha256 of
  runtime.lock>/` with the base interpreter (`python -m venv`, then `pip install
  --require-hashes --no-deps --only-binary=:all:`), after checking the kit wheel against
  `kit.lock`, and switch the link `tools/.runtime/current` only once it imports. Every
  other command runs `tools/.runtime/current/bin/python` by absolute path and stops with
  one line naming `papaia-ctl setup` when the environment, or the base interpreter,
  standard library and shared Python library it runs on, is missing, stale, group- or world-writable, or owned by
  another account than root or the owner of `tools/`. On a checkout without an
  environment, `hostnames`, `doctor` and `restore` build it as `setup` does, so the
  documented fresh installation and the restore after the loss of the host need no
  `setup` first. Every Python step runs isolated (`-I`, `-P`), so a module in the caller's
  working directory never runs instead of the hash-checked code. PATH
  and sudo's `secure_path` no longer decide which Python runs, so `sudo tools/papaia-ctl
  pairing approve` from a second account works without a change to its sudoers rule.
- The upgrade builds the target's environment before the plan runs on it; environments
  are kept by lock, so `rollback` returns to the previous one, and `upgrade --finalize`
  removes those no restore point needs; when the release tag of a restore point is not in
  the checkout, it removes none and warns. New `doctor` check `ctl_runtime`.
- The documented floor is Python 3.12 with the `venv` module (README, `find_python`,
  `pyproject.toml`, nodes); PyYAML is no longer installed by hand. `PAPAIA_PYTHON=/absolute/path`
  names the base interpreter; a name or a relative path is refused. pip reads a mirror
  (`PIP_INDEX_URL`) or a wheel directory (`PIP_FIND_LINKS`) from the environment; hashes
  are required in every case.
### Release version check of a version tag

- A tag `vX.Y.Z` fails before anything is built, signed or published unless `VERSION` is
  exactly `X.Y.Z` (no pre-release part, no build metadata) and the tag is `v` + `VERSION`:
  new job `release-version` of the "Core images" workflow
  (`python -m lib.release_version check --tag <ref>`); every later job needs it. A core
  with a pre-release `VERSION` accepts the test trust anchor, so a tagged release must
  never carry one. The check is item 7 of the release gate in `docs/compatibility.md`.
- ADR 0030 (test trust anchor for pre-release cores) is accepted.

### Fixed zstd and zlib in the Debian-based core images

- `papaia-egress`, `papaia-lifecycle`, `papaia-replay`, `papaia-people`,
  `papaia-chat-relay` and `papaia-docker-gate` carry `libzstd1` `1.5.7+dfsg-1+deb13u1`
  (CVE-2026-124851) and `zlib1g` `1:1.3.dfsg+really1.3.1-1+deb13u1` (CVE-2026-85091) on
  linux/amd64 and linux/arm64. A stage on the build platform fetches exactly these
  versions from the Debian archive of the base and the final stage only copies the
  result; the base digest is unchanged. The six images are rebuilt and re-pinned.

### Final kit 0.1.0

- The core vendors the final kit 0.1.0, the release build of kit commit `849e344`
  (`tools/vendor/papaia-kit/0.1.0/`, `tools/kit.lock`, `tools/pyproject.toml`,
  `tools/uv.lock`); the kit folded its earlier local cuts into this release. The register
  and schema snapshots name the final commit; the login theme resources are unchanged.
- `compat/suite-kit.yaml` names the kit build of every repo (`kit_build`: version, commit,
  wheel sha256) and the kit's commit, since the version alone does not tell two builds of
  0.1.0 apart. `qdrant-mcp-rbac` still vendors an internal kit cut and has no `kit` field
  until it binds the release.

### Data class of every model route

- Every alias of the model gateway carries the highest data class its route may receive
  (`model_info.papaia_max_class` from the overlay, else `PAPAIA_MODEL_MAX_CLASS` in the root
  `.env`, else `internal`). A value outside the kit scale stops the render; a value from a
  repository, profile or add-on layer is dropped and reported; a hosted test model is capped
  at `internal`; an alias with several deployments or fallbacks gets the lowest class it can
  reach.
- The render writes `ai/litellm/model-routes.json` (alias to class, no key), mounted
  read-only into the gateway; each changed class is one `config_changed` audit row.
- The platform catalog fills its `models` block with every alias (`alias`, `features`,
  `context`, `max_class`, `test_backend`).
- A module need's `max_class` must be a class of the kit scale; module keys store the
  declared classes (`metadata.papaia_need_classes`) and are replaced when they change.
- `papaia-ctl addon start` and the new check `doctor model_gateway_classes` report a need
  above the class of its route; `doctor` fails when the route file is missing or differs.

### Refusal above the route class at the model gateway

- New pre-call hook `papaia_class_guard`, registered right after the halt hook: every model
  call made with a module key is judged before any backend call. The request class is the
  header `x-papaia-data-class`, else the module's declared class for the alias, else the
  highest class; a request above the route class or above the declared class is refused
  with `403 class_exceeded`, a malformed header with `400 invalid_data_class`, and every
  module call with `503 route_class_unknown` while the route file is missing, unreadable or
  lacks the alias. The platform halt still refuses first; the master key is not judged.
- Refusals carry `x-papaia-error-code` and `x-papaia-correlation-id`, and each is one
  `papaia.audit/1` row (writer `litellm/class-guard`, no content, no key) in the gateway's
  own outbox `audit/outbox/litellm.jsonl` (counter `litellm.seq`), made by the render and
  mounted read-write into the gateway alone.
- Module keys are made with a route list (`allowed_routes`): chat completions, embeddings
  and the model listing; every other gateway route answers `403`. Keys made without it are
  replaced at the next start.

### Decision: data class of a model route

- ADR 0031 decides that every model route carries the highest data class it may receive
  (from the overlay, else `PAPAIA_MODEL_MAX_CLASS`, else `internal`; a hosted test model
  never above `internal`), that the platform catalog publishes it in its `models` block, and
  that the model gateway refuses a module request above the route or above the module's
  declared class before any backend call (`403 class_exceeded`, `400 invalid_data_class`,
  `503 route_class_unknown` when route data is missing), with one audit row per refusal.
  Module keys reach only the model call routes the gateway judges; keys made before the
  check are replaced at the next start. Route classes and the gateway check are not
  implemented yet.

### Decision: tool servers outside the suite in the chat

- ADR 0029 decides how a tool server outside the suite (`trust: addon`) reaches the chat:
  only through a core relay, `papaia-chat-relay`, that exchanges the chat token for a token
  with exactly the add-on's audience, after a per-add-on opt-in of the operator (off by
  default, a second host account for writes and under the four-eyes setting). The add-on
  never receives the shared chat token; opt-in, revoke and every relayed call are audited.

### Opt-in of a tool server outside the suite for the chat

- `papaia-ctl addon chat allow|revoke|list`: the operator allows an installed add-on outside
  the suite (one tool server for persons, at least one tool) for the chat. A module of the
  suite, an unknown name, an add-on that attaches `librechat` and an audience that exchanges
  tokens are refused. `allow` shows audience, tools, effects and the data class cap and asks;
  without a terminal `--approve=<audience>` names what was shown, `-y` is refused. A write
  opt-in, and every opt-in under the four-eyes setting, waits for a second host account.
  The opt-in is the pairing `papaia-chat-relay` → `<audience>` in `security/pairings.yaml`;
  `pairing approve`, `pairing revoke` and the bill of materials refuse that client.
- A confirmed opt-in of a running add-on whose declared effects still match is written to
  the relay's list `chat-relay/servers.json` and gets a chat entry named after its audience
  that points to `http://papaia-chat-relay:8080/servers/<audience>/mcp`, its description
  ending with the data class cap. No audience mapper of the add-on goes on `librechat`; the
  catalog entry keeps `trust: addon`. Revoke, uninstall and stop take it off the list at
  once.
- One `papaia.audit/1` row of `papaia-ctl/chat-relay` per decision and refusal
  (`chat_relay.allow`, `chat_relay.approve`, `chat_relay.revoke`) and per write of the list
  (`chat_relay.list_write`).

### Chat relay for tool servers outside the suite

- New core service `papaia-chat-relay` (profile `librechat`, own image
  `ghcr.io/fidonis/papaia-chat-relay`): the chat calls a tool server outside the suite at
  `/servers/<audience>/mcp`; the relay checks the person's chat token, checks the tool and
  its arguments against its list of allowed servers, exchanges the token at the identity
  provider for a token with exactly the add-on's audience (RFC 8693, `private_key_jwt`) and
  forwards the call with it. The add-on never receives the chat token. `tools/list` is
  answered from the list; every method other than the tool methods is refused. Limits:
  1 MiB request, 8 MiB answer, 60 s for the whole call however slowly the add-on sends,
  60 calls per minute per person and add-on, 128 requests at a time (503 `busy`); no retry,
  no fallback. One `papaia.audit/1` row per request on the container's stdout.
- `papaia-ctl realm sync` manages the client `papaia-chat-relay` while at least one opt-in
  pairing is confirmed: token exchange only, no refresh token, `fullScopeAllowed: false`,
  the client policy `chat-relay` (subject token from `librechat` only), the audience mapper
  on `librechat`; the client is deleted when the last opt-in goes. A pairing of the relay
  with a suite server, a core audience or an add-on that attaches the chat stops the sync.
- `papaia-ctl start` makes the relay's key under `security/chat-relay/` and the folder of
  its list `chat-relay/`.
- The core vendors papaia-kit 0.1.2, which registers the relay's audience, client and
  scope.

### Mein Bereich at the connection registry

- With the profiles `me` and `connections` both on, `me-web` gets a client certificate of
  the platform PKI next to its server certificate. A core `pki.yaml` may tie a client
  certificate to further profiles (`client.with_profiles`).
- New generated override `docker-compose.me-connections.override.yml`: `me-web` joins
  `papaia-connections-net` only while both profiles run on the host, with its certificate
  directory read-only and the paths `ME_CONNECTIONS_CA_FILE`, `ME_CONNECTIONS_CERT_FILE` and
  `ME_CONNECTIONS_KEY_FILE` (listed under `with_profiles` in `src/infra/me/service-env.json`).
  The registry's `CONNECTIONS_PERSON_CLIENTS` gets `papaia-me` while `me` is on, and keeps
  the operator's value. Each change of the override is one `papaia.audit/1` row.
- `me-web` is no longer on `papaia-connections-net` in the base compose file.
- The pairing `papaia-me` -> `papaia-connections` may hold the effects `r` and `d` only;
  the realm sync refuses any other effect for it. It is approved by a second host account.

### Test trust anchor for pre-release cores

- `start`, `upgrade`, `pairing list`, `pairing confirm` and `suite verify` take
  `--test-trust-anchor=FILE` on a pre-release core: for that one command a bill of materials
  of scope `test` signed with the key in FILE is accepted, and images are checked against
  that key. A release core refuses the option before reading anything else; the `delivery`
  path and the pinned `compat/release-key.pub` are unchanged. A banner opens and closes the
  command, and every use writes one `papaia.audit/1` row (event `test_trust_anchor_used`).
  No environment variable or configuration entry enables it (ADR 0030).

### Information and erasure in chat, model gateway and identity provider

- `papaia-ctl person run` now covers the core services: the chat by the person's `sub`
  (a login of the chat database made for the one call and dropped after it), the model
  gateway's usage by `sub`, chat account or mail, and the identity provider's account,
  groups, roles, consents and sign-in events through `svc-papaia-lifecycle`, whose purpose
  now names this; no further account gets `manage-users`.
- An erasure disables the account and ends its sessions first and deletes it last; when a
  step fails the account stays disabled and the request ends `partial`. The core writes the
  journal entries `core-chat` and `model-gateway`, and reconciles afterwards: every place
  that still names the person by `sub`, chat account or mail is listed with its count and
  makes the request `partial`; every core row without a path is named `not checked`. A
  failed deactivation erases nothing; without the `lifecycle` profile the output notes
  that the account was not disabled first.
- The gateway's erase removes the end-user records only. Its per-request usage rows and
  daily sums under the chat account id, and the container logs of chat and gateway, are
  listed as not included with their retention; the proof says `not erased
  model-gateway/usage_rows`.
- New `doctor model_gateway_content`: `fail` when the model gateway would keep request or
  response content.

### German operator handbook

- `docs/de/betrieb/handbuch.md` is the entry of the German operator handbook. New chapters:
  size profiles with the default model and the share of each core profile and module
  (`groesse.md`), the communication matrix and the egress list (`netz.md`), the module
  dependency matrix with adding and removing modules (`module.md`), restart and long-run
  behaviour (`neustart-und-dauerlauf.md`), the troubleshooting guide S-1 to S-10 that
  `doctor` and the start gate cite (`stoerungen.md`), hypervisor snapshots and copies outside
  the house (`sicherung.md`). The data subject request names the identity check, the deadline
  and the list of erasure proofs.
- `tools/tests/test_operator_handbook_de.py` holds the handbook to the repository: profile
  values, counts per core profile, the rows of `security/comm-matrix.yaml`, the cited guide
  sections and every `papaia-ctl` command and `doctor` check it names (read from
  `papaia-ctl help`). With `PAPAIA_HANDBOOK_ADDONS` it also compares the module rows with the
  add-on manifests and Compose files.

### Sign-in addresses of add-on clients (add-on contract generation 18)

- New optional manifest key `client_addresses`: for a confidential client it owns in the
  names register, an add-on names the redirect paths, post-logout paths, back-channel logout
  path and web origin on one of its own interfaces (`integration.nginx`). The realm sync sets
  exactly these addresses on the host the installation gives that interface (scheme and port
  of the edge) and removes the ones the manifest no longer declares; the hardening step keeps
  them. An add-on such as Flow no longer needs an administrator to enter its addresses by
  hand (ADR 0028, `docs/client-addresses.md`).
- A client without the key keeps what it has; the realm sync output for manifests without it
  is unchanged. When the declaration goes, or the add-on is removed or disabled, the
  client's addresses go; `addon uninstall` deletes the client with them.
- `compat` refuses, naming the entry: a client of another add-on, a core client, a public,
  bearer-only or exchange-only client, an unknown host key, a path with a wildcard, query,
  fragment, `..`, `//` or percent-encoding, more than 8 redirects. `ADDON_API` `current=18`
  (`min` stays 1); a core below 18 reports the add-on `INCOMPATIBLE` (`client_addresses`).
- Realm hardening now removes a post-logout redirect list by sending it empty, as Keycloak
  keeps an attribute an update leaves out.

### Signing in to Mein Bereich (profile `me`)

- `src/infra/me/exposes.yaml` declares the profile for the realm sync: while `me` is on, it
  plans the sign-in client `papaia-me`, the bearer client of the audience `papaia-prefs` and
  the role `prefs-read` (`realm_sync.CORE_PROFILE_MODULES`); with the profile off, none of them.
- `start` creates `papaia-me` with the generated `ME_OIDC_CLIENT_SECRET` and aligns its secret
  (`keycloak_role_sync.CORE_PROFILE_SIGN_IN`); the client redirects only to
  `<ME_PUBLIC_URL>/auth/callback`.
- The realm sync writes the `azp` allow-list of `prefs`, `security/azp/azp-allowlist.json`,
  from the confirmed and assigned pairings with `papaia-prefs` only (a write pairing after the
  second person's approval), replaced in one step and removed with the profile. It pairs
  `papaia-me` with `papaia-audit` (effect `x`) itself while `audit` is on.
- `setup`, `start` and the add-on commands write the module list of Mein Bereich,
  `personal-settings/registry.yaml`, from the `personal_settings:` sections of the active
  add-ons, and `personal-settings/module-ca/<module>.pem` from the platform PKI. Every write
  is one `papaia.audit/1` row (writer `papaia-ctl/me-area`).
- The README no longer lists the known limit of the profile.

### TLS to the module services under `kritis`

- Under `PAPAIA_SECURITY_PROFILE=kritis` the proxy forwards to Flow, the assistant and
  Me (`me-web`) with https. It checks the certificate against the platform CA under the
  service's name and presents its own client certificate (`src/infra/nginx/pki.yaml`).
  `npm-provision` corrects a host that still forwards in plain HTTP. The host of the main
  address names `me-web` with the same upstream.
- Keycloak calls Me's back-channel logout at `ME_PUBLIC_URL` through the proxy instead of
  `http://me-web:8000`, which listens with TLS of the platform CA only under `kritis`.
- The catalog gives Flow, the assistant and the connection registry https addresses under
  a name their server certificate covers, so Me calls the assistant over TLS.
- `me-web` gets a server certificate (`src/infra/me/pki.yaml`). Under `kritis` the
  override `docker-compose.module-tls.override.yml` lets it listen with TLS and check the
  modules it calls against the platform CA.
- A module service without a server certificate for its name stops the render instead of
  being forwarded in plain text. `standard` is unchanged.

### Restore after the loss of the host

- Every restore point carries an unencrypted `RELEASE` file (core tag, suite, installation
  id); `<target>/latest/` names the newest good point of the whole installation, and
  `restore --restore-point=latest` restores it.
- `restore --from=<target>` names the source; on a host without a setup it restores the whole
  point, checks `.papaia-target` and brings the configuration back. A whole restore stops
  before any change when the checkout is another release and names `git checkout <tag>`.
  `backup key-check` takes `--from` as well; `restore --backup-dir` still works.
- Erasure probe after every restore that starts the modules: each module with deletions
  journaled since the point must have applied its journal in this restore, otherwise the
  restore exits with code 3. One audit row `erasure_probe` and `erasure_probe=` in
  `backup.log`.

### Offered add-on networks (add-on contract generation 17)

- New optional key `network` in a `networks.join_addons` entry: the listed services join the
  internal network the required add-on offers through an `exposes` entry (its
  `address.service` is on it) and never that add-on's `app_network` (ADR 0027,
  `docs/offered-networks.md`). Written to
  `overrides/addons/docker-compose.<name>-offer-<target>.override.yml`.
- `ADDON_API` `current=17` (`min` stays 1); the generation table, `GENERATION_FEATURES`
  (`networks.join_addons.network`), the contract snapshot and the suite matrix carry it.
- The compatibility check refuses, naming the entry, an unknown field, a network not scoped
  to the target, a core network, a network the target does not create with
  `internal: true` or has no `exposes` address on, the target's app, egress or isolated
  network, and a manifest whose `requires.addon_api` names a generation below 17 (an older
  core would otherwise join the app network). `--force` does not let these through.
- An optional target that is not installed or not active is skipped with a warning naming
  target and network; the consumer starts. A missing offered network at `addon start` is
  left out with a warning instead of a failed start; `doctor addon_compat` reports it.
- Entries without the key render byte-identical to before.

### Isolated add-on networks (add-on contract generation 16)

- New manifest key `networks.isolated: [{network, attach: [litellm]}]`: internal networks of
  an add-on that the core joins with LiteLLM and nothing else, so a service that reads
  foreign content shares a network with the model gateway alone (ADR 0026,
  `docs/isolated-networks.md`).
- `ADDON_API` `current=16` (`min` stays 1); the generation table, `GENERATION_FEATURES`,
  the contract snapshot and the suite matrix (`compat/suite.yaml`) carry it.
- The compatibility check and the override render refuse, naming the entry, a service other
  than `litellm` (`ISOLATED_ATTACHABLE`), an empty `attach`, a network that the add-on's
  compose file does not create with `internal: true`, the add-on's own `app_network` or
  egress network, a duplicate entry, a core or Docker network, and a name not scoped to the
  add-on; the render also refuses a network another add-on declares. A core below
  generation 16 reports such an add-on `INCOMPATIBLE`.
- `addon install`, `start`, `upgrade`, `rollback`, `check` and `list` pass the add-on's
  directory to the check, so its compose file is read. Overrides of add-ons without the key
  are byte-identical.

### Diagnostics: causes, logs, support bundle and metrics

- `papaia-ctl doctor` names the cause of every failing check in one German sentence with the
  section of the troubleshooting guide (`siehe Handbuch §S-n`), also as `causes` in `--json`.
  New checks `model_gateway`, `model_ready`, `halt` and `realm`; an unreachable mail server is
  now `fail`.
- New commands `papaia-ctl logs`, `papaia-ctl support-bundle` and `papaia-ctl metrics`.
- Every core service rotates its log (json-file, 5 x 10 MiB); active add-ons get the same
  through a generated override.
### Edge refuses platform writes from Studio app hosts

- Every proxy host of the bundled proxy refuses a request other than `GET`, `HEAD` or
  `OPTIONS` whose `Origin` is a Studio app host (`apps.<domain>`, `INGRESS_APP_DOMAIN`, or a
  host below one of them) with `403` and `X-Papaia-Error: app_origin_refused`, and writes one
  `papaia.audit/1` line (`protected_host_denied`, writer `papaia-edge`) to
  `infra/nginx/nginx-data/logs/papaia-audit.log`. `npm-provision` installs the rule into the
  proxy manager's `http_top.conf` and `server_proxy.conf`, tests the configuration and rolls
  it back when the proxy refuses it.
- New `doctor edge_app_origin`: the refusal is in place, and no platform cookie (identity
  provider, forward-auth proxies, modules, read as an anonymous browser) carries a `Domain`
  that covers an app host.

### Kit 0.1.0 in the core tools

- The core tools vendor papaia-kit 0.1.0, the kit's first public release (MIT): wheel and
  source tarball under `tools/vendor/papaia-kit/0.1.0/`, pinned in `tools/kit.lock` and
  `tools/uv.lock`. The contract schemas are byte-identical to those of the previous kit;
  the schema snapshot and the naming register snapshot now name kit 0.1.0.
- `tools/kit_snapshot.py` writes and checks the schema and naming register snapshots from
  the vendored kit; CI fails when they differ.
- Suite bill of materials: optional per-repo field `kit` (`version`, `renders_ui`) in the
  kit's own shape; `papaia-ctl suite verify` validates it. `compat/suite-kit.yaml` holds
  the kit versions of the candidate suite, and CI runs the kit's `pk-check bom` over it.
- License document (`docs/de/betrieb/lizenz-und-bezug.md`): Studio and the kit are listed
  under MIT without a NOTICE remark; the Studio row names the license files in its images.
  A test checks that the kit row, the kit entry of `THIRD_PARTY_LICENSES.md` and the
  vendored wheel agree on license and version.

### Permission report built by papaia-audit

- papaia-audit builds the permission report: `POST /v1/access-reports/build` with
  `{"by", "format"}` for a person with `papaia-auditor` (token exchange by
  `papaia-manager`). `papaia-ctl report permissions` calls it and no longer signs in as the
  Keycloak administrator.
- **Removed:** `POST /v1/access-reports` (release of a report built on the host). A client
  that still calls it gets `404`.
- New core account `svc-papaia-audit-report` (profile `audit`) with `realm-management`
  `view-users` only, the internal network `papaia-audit-idp-net` between papaia-audit and
  Keycloak (row K-21), and the inputs file `infra/audit/service/access-report-inputs.json`
  written by `papaia-ctl realm sync`. Run `papaia-ctl realm sync` after the upgrade before
  the first report.

### Upgrade notice: installations with Paperless

This is the first release that puts the gate `paperless-gate` in front of Paperless.
Copy this notice into the release notes of the release.

- **Who is affected.** Installations up to 1.9.x that run the Paperless add-on.
- **Effect.** In those installations, Paperless could accept a request that did not come
  through the platform's sign-in as a request of a signed-in person. Documents could then
  be read or changed under another person's name.
- **Remedy.** Install this upgrade soon: the core release and the Paperless add-on from
  papaia-addons 1.4.0 or later, both together. The add-on releases before papaia-addons
  1.4.0 do not have the gate, and that includes Paperless add-on version 2.0.0: an
  installation on 2.0.0 is affected. After the upgrade, Paperless answers only requests
  that come through the platform's proxy or its MCP server, and the person's name is
  accepted only for accounts the platform knows.
  1. `tools/papaia-ctl upgrade --identity=<file>` moves the core; its setup step
     creates the proxy's own secret for the gate.
  2. `tools/papaia-ctl addon upgrade paperless --path=<directory of the add-on from
     papaia-addons 1.4.0 or later>` moves the add-on. `addon install`, `addon upgrade`
     and `addon rollback` refuse a Paperless add-on whose `docker-compose.yml` has no
     service `paperless-gate`.
  3. Check that the gate runs: `docker ps --filter name=paperless-gate --format
     '{{.Names}} {{.Status}}'` must list one running container. If it lists none, the
     installation is still affected.
  4. `tools/papaia-ctl doctor` must end with exit 0.
- **Until the upgrade is installed**, keep the Paperless add-on stopped
  (`tools/papaia-ctl addon stop paperless`) if it can be reached from anywhere but the
  platform's proxy.
- **Release check.** `setup` offers Paperless only when the signed bill of materials of
  the release lists the gate (`component: paperless-gate`); a release without it does
  not offer Paperless at all.

### Changed

- Mail relay: every mail leaves `smtp-relay` with one sender, the name of the
  installation (`name` in `overlay/platform/branding.yaml`) and the configured address;
  a `Sender` header is dropped. `--smtp-from-name` is accepted only when it repeats that
  name, and setup no longer asks for a sender name. A mail with an attachment or a part
  that is not text, HTML or an image is refused with `550 5.7.1`.

### Removed

Descriptions replaced by `exposes:` in this release (no parallel operation):

- The hand-written LibreChat fragment and the `librechat` audience mapper of a tool
  server declared in `exposes:` with `kind: mcp` and `trust: platform`: the core
  generates both from the platform catalog. A `client_mappers.librechat` export for
  such an audience is no longer a manual step with the bundled Keycloak. A fragment an
  add-on still ships is kept for that add-on until the add-on drops it.
- Free tool names in `knowledge.sources[].access[].key_tools` of a module that declares
  `exposes`: they must be operation names of its `exposes`; `addon check` refuses others.

### Fixed

- `papaia-chat-relay` is pinned again to the digest its source builds to
  (`sha256:28cc8410…`, two clean builds give the same digest); the compose file still
  pinned a build from before the last change to `src/infra/chat-relay/`, so an
  installation ran an image that did not match its source and the own-images check
  failed. No other pin changes.
- `papaia-ctl rollback` is no longer refused on a busy host with "has no 'rollback'
  command" for a release that has the command: the check read the release's
  `tools/lib/sh/upgrade.sh` through a pipe into `grep -q`, and under `pipefail` the early
  end of `grep` could fail the check. The output is now read first, then matched. A
  release whose upgrade script cannot be read gets its own error with git's message; a
  release without the command is refused as before.
- The Keycloak certificate check reads the output of `openssl x509 -text` before it
  matches, so a current certificate is no longer issued again on a busy host. An
  unreadable certificate is still issued again.
- A static test fails when a pipeline in `tools/papaia-ctl` or `tools/lib` ends in a
  reader that stops early (`grep -q`, `grep -m`, `grep -l`, `head`, `sed -n '…q'`).

## [1.10.0-rc.1] - 2026-11-23

Release candidate of 1.10.0 (suite 1.10.0). It is not published: its images are served
from a test registry until the release publishes and signs them. The changes are the ones
listed under [Unreleased].

- `VERSION` is `1.10.0-rc.1`. The start check reads the bill of materials of suite
  1.10.0 (`compat/suite-1.10.0.yaml`) and prints "(candidate)".
- The own images papaia-audit, papaia-docker-gate, papaia-egress, papaia-lifecycle and
  papaia-people are rebuilt with `tools/build-images build` for linux/amd64 and
  linux/arm64 and pinned as `<name>:1.10.0-rc.1@sha256:<digest>`.
- papaia-manager 1.8.0 is pinned (`ghcr.io/fidonis/papaia-manager:1.8.0@sha256:<digest>`),
  the manager range of suite 1.10.0 (`>=1.8.0,<1.9.0`).
- `tools/check-image-pins check --mode=candidate` resolves the own images and the
  manager in the test registry. The pins of papaia-me and papaia-connections move with
  their releases.
- The release re-pins every image to its published digest (docs/compatibility.md,
  "Pinned images resolve") before the 1.10.0 tag.

## [1.9.0] - 2026-11-20

### 🚀 Features

- feat: switch the knowledge map like the other optional modules (#410) @marko-boehm
- feat: knowledge map as an optional core profile with inventory and governance checks (#394) @WilhelmSebastian
- feat(localai): manage the native localai through launchd (#389) @fwahl711
- feat(localai): run localai natively on apple silicon macs (#388) @fwahl711
- feat(librechat): add a command to clear a user's chat history (#375) @fwahl711
- feat(localai): register the local models in litellm and authenticate with an api key (#373) @fwahl711
- feat: add local voice (stt and tts) as an optional core profile (#393) @WilhelmSebastian
- feat(ctl): pull images quietly when stderr is not a terminal (#374) @fwahl711
- feat(keycloak): create add-on clients and their secrets automatically (#334) @fwahl711
- feat(librechat): let add-ons provide agents and prompts (#321) @fwahl711
- feat(addon): add add-on defined maintenance actions and addon run (#319) @fwahl711
- feat(addon): fill an env prompt from a value another add-on exports (#317) @fwahl711
- feat(addon): let selected services join a required add-on's network (#315) @fwahl711
- feat(addon): let an add-on require other add-ons (#312) @fwahl711
- feat(setup): support papaia-manager on docker desktop for macos (#299) @fwahl711

### 🐛 Bug Fixes

- fix(mcp-firecrawl): serve on node port 3000 after the image dropped nginx (#425) @marko-boehm
- fix(keycloak): disable hsts while plain-http services share the auth hostname (#377) @WilhelmSebastian
- fix(uninstall): delete root-owned data in the config dir through a container (#371) @fwahl711
- fix(librechat): bump mongo to 8.3.17 for Linux >= 6.19 (#385) @WilhelmSebastian
- fix(addon): describe a managed client's secret as generated in the checklist and plan (#384) @fwahl711
- fix(librechat): keep an operator agent while its file fails and drop all its acl entries (#383) @fwahl711
- fix(librechat): derive mcp tool keys for provisioned agents with an empty tools list (#376) @WilhelmSebastian
- fix(addon): check dependents when install re-points an installed add-on (#370) @fwahl711
- fix(setup): apply the stored auth_host rules to the interactive prompt (#342) @fwahl711
- fix(certs): keep the local ca key private and limit what the ca can sign (#355) @fwahl711
- fix(librechat): share provisioned agents and clean up their old documents (#360) @fwahl711
- fix(keycloak): verify the host_ip connection as strictly as the default (#344) @fwahl711
- fix(librechat): store provisioned agents under an agent_ id (#309) @fwahl711

### 📖 Documentation

- docs: lift the experimental flag off the distributed mode (#387) @WilhelmSebastian
- docs(distributed): close validation-runbook gaps found in #262 (#386) @WilhelmSebastian
- docs: describe how to replace an older local ca (#379) @fwahl711
- docs: update five image versions in the third-party licenses (#357) @fwahl711

### 🧹 Maintenance

- chore: bump papaia-manager to 1.7.0 (#426) @marko-boehm
- chore(rag): bump qdrant-mcp-rbac to 0.4.2 (#397) @fwahl711
- test(golden): record the compose output after the latest image bumps (#390) @marko-boehm
- chore(deps): bump firecrawl/firecrawl-mcp-server from `77f1a6f` to `d9015c8` in /src/ai/mcp-firecrawl (#364) @dependabot
- chore(deps): bump localai/localai from v4.7.1 to v4.12.1 in /src/ai/localai (#363) @dependabot
- chore(deps): bump prom/prometheus from v3.15.1 to v3.16.0 in /src/ai/litellm (#362) @dependabot
- chore(deps): bump firecrawl/firecrawl from 2.11.703 to 2.11.705 in /src/services/firecrawl in the compose-patch group across 1 directory (#361) @dependabot
- test(golden): record the compose output after the image bumps (#351) @marko-boehm
- chore(deps): bump prom/prometheus from v3.13.1 to v3.15.1 in /src/ai/litellm (#349) @dependabot
- chore(deps): bump librechat-ai/librechat-rag-api-dev-lite from v0.8.0 to v0.9.0 in /src/ai/librechat (#347) @dependabot
- chore(deps): bump mongo from 8.0.20 to 8.3.13 in /src/ai/librechat (#346) @dependabot
- chore(deps): bump the compose-patch group across 4 directories with 3 updates (#345) @dependabot
- chore(litellm): bump proxy image to v1.108.3 (#352) @marko-boehm

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.8.0...v1.9.0

## [1.8.0] - 2026-11-07

### 🚀 Features

- feat(addon): let a manifest add steps to the install checklist (#278) @fwahl711
- feat(topology): run an installation on several nodes (#267) @fwahl711
- feat(keycloak): brand the login page for logins started by papaia services (#261) @marko-boehm
- feat(addon): add upgrade, rollback and list verbs (#253) @marko-boehm
- feat(backup): back up part of the installation with --only (#252) @marko-boehm

### 🐛 Bug Fixes

- fix(setup): keep the stored AUTH_HOST when --auth-host is not given (#257) @WilhelmSebastian
- fix(keycloak): reach the published port on HOST_IP in keycloak-role-sync (#258) @WilhelmSebastian
- fix(ctl): find any python3.x on path and fix the macos install hints (#328) @fwahl711
- fix(topology): refuse a config dir that does not keep file modes (#274) @fwahl711
- fix(mcp-firecrawl): run the amd64-only image emulated on arm64 hosts (#294) @fwahl711
- fix(setup): default papaia-manager to off on macos (#295) @fwahl711
- fix(certs): issue a keycloak certificate that macos accepts (#293) @fwahl711
- fix(ctl): expand empty arrays safely under bash 3.2 (#291) @fwahl711
- fix(ctl): reject python older than 3.10 in the preflight (#292) @fwahl711
- fix(lifecycle): recreate containers on docker desktop (#276) @fwahl711
- fix(oauth2-proxy): keep the csrf nonce per login request (#275) @fwahl711
- fix(backup): let a whole-stack restore through target validation (#259) @WilhelmSebastian

### 📖 Documentation

- docs: list haproxy in the third-party licenses (#339) @marko-boehm
- docs: add an opt-in guide for parallel search mcp in librechat (#297) @fwahl711
- docs: document macos prerequisites and limitations (#296) @fwahl711
- docs: add a code of conduct (#277) @fwahl711

### 🧹 Maintenance

- chore: bump qdrant-mcp-rbac to 0.4.1 (#340) @marko-boehm
- chore: bump papaia-manager to 1.6.0, qdrant-ingest to 1.0.1 and jina-reranker-api to 0.1.3 (#337) @marko-boehm
- ci: scan the compose images for known vulnerabilities (#280) @fwahl711
- ci: propose compose image updates (#281) @fwahl711
- ci: run ruff and pytest on every pull request (#279) @fwahl711

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.7.0...v1.8.0

## [1.7.0] - 2026-10-24

### 🚀 Features

- feat: list the bundled component versions with papaia-ctl addon components (#247) @marko-boehm

### 🐛 Bug Fixes

- fix(addon): address an add-on without compose file by project name (#245) @marko-boehm

### 🧹 Maintenance

- chore: bump papaia-manager to 1.5.0 (#248) @marko-boehm

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.6.0...v1.7.0

## [1.6.0] - 2026-10-19

### 🚀 Features

- feat(modules): preview overlays and delete a module's data or settings (#239) @marko-boehm
- feat(smtp): add an optional smtp-relay profile (#233) @marko-boehm
- feat: give papaia-admin keycloak's user and role administration rights (#231) @marko-boehm

### 🐛 Bug Fixes

- fix(keycloak): reach keycloak from the role sync inside a container (#236) @marko-boehm

### 🧹 Maintenance

- chore: bump papaia-manager to 1.4.0 (#241) @marko-boehm
- chore: bump qdrant-mcp-rbac to 0.4.0 (#240) @marko-boehm

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.5.0...v1.6.0

## [1.5.0] - 2026-10-10

### 🚀 Features

- feat(rag): pass the metadata and ACL collection names to both services (#227) @marko-boehm
- feat(setup): install the rag system by default in the wizard (#224) @marko-boehm
- feat(setup): ask for the rag system during setup (#216) @marko-boehm
- feat(rag): add optional rag profile with qdrant, mcp and ingest (#215) @marko-boehm

### 🐛 Bug Fixes

- fix(ctl): parse --config-dir for npm-provision and keycloak-role-sync (#218) @marko-boehm

### 🧹 Maintenance

- chore(librechat): bump librechat to v0.8.8 (#226) @marko-boehm
- refactor(rag): drop the ingester web interface integration (#222) @marko-boehm
- chore: bump papaia-manager to 1.3.0 and qdrant-ingest to 1.0.0 (#220) @marko-boehm

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.4.0...v1.5.0

## [1.4.0] - 2026-10-03

### 🚀 Features

- feat(doctor): read gpu and time_sync from a container and report docker usage (#210) @marko-boehm
- feat(doctor): add memory, cpu, gpu and time sync checks (#208) @marko-boehm
- feat: add status and doctor commands (#206) @marko-boehm

### 🧹 Maintenance

- chore: bump papaia-manager to `1.2.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.3.0...v1.4.0

## [1.3.0] - 2026-09-28

### 🚀 Features

- feat(litellm): ship no default models and make librechat models configurable (#202) @marko-boehm
- feat!: split the shared Keycloak admin role into per-service admin roles (#198) @marko-boehm

### 🐛 Bug Fixes

- fix: add new .env.example variables to the active .env on start (#200) @marko-boehm
- fix(addon): scope the Seam-1 network to the deployment (#194) @marko-boehm
- fix(papaia-ctl): check for PyYAML in preflight and document it (#192) @marko-boehm
- fix(keycloak): generate the bootstrap admin password (#191) @marko-boehm

### 🧹 Maintenance

- chore: bump litellm to v1.100.0 (#196) @marko-boehm
- chore: bump papaia-manager to `1.1.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.2.0...v1.3.0

## [1.2.0] - 2026-09-04

### 🚀 Features

- feat: `papaia-ctl backup-delete --restore-point=ID` — delete specific restore points (the snapshot directory and its `backup.yaml` catalogue entry) for cases the age-based `backup --retention-period-days` is too coarse. `--restore-point` is required, repeatable, and accepts comma-separated values; every id is validated against the catalogue before anything is removed, so one unknown id aborts the whole call. The running stack is not touched; each deletion is recorded in `backup.log`

### 🐛 Bug Fixes

- fix(addon): `addon start <name>` now resolves an add-on's compose overrides in `overrides/addons/` by longest registered-name match instead of a `docker-compose.<name>-*.override.yml` glob, so starting an add-on whose name prefixes another's (e.g. `qdrant` vs. `qdrant-ingest`) no longer pulls in the other add-on's override files and aborts with "neither an image nor a build context specified"
- fix(upgrade): `upgrade` now hands off from phase 1 to phase 2 through `"${BASH:-bash}"` instead of `exec`-ing `tools/papaia-ctl` by path, since the preceding `git checkout <tag>` rewrites that tracked file and made the direct `execve()` fail with exit 126 right after "Moving the checkout to <tag>...". `tools/papaia-ctl` is also now tracked executable (`100755`)

### 🧹 Maintenance

- chore: bump papaia-manager to `1.0.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.1.0...v1.2.0

## [1.1.0] - 2026-09-02

### 🚀 Features

- feat: `papaia-ctl restore --only=SELECTOR[,SELECTOR]` — scoped restore. `module:NAME`, `addon:NAME` or `volume:NAME` selectors limit the teardown and the restart to the units the selection touches; everything outside it keeps serving. Backup manifests gain a v2 form recording `project`, `module`, `services` and `profiles` per artifact (v1 manifests still restore as a whole). Refuses `--restart-clean`, a config-directory selection, or a selection that resolves to the `manager` profile

### 🧹 Maintenance

- chore: bump papaia-manager to `0.6.0`

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v1.0.0...v1.1.0

## [1.0.0] - 2026-08-03

### 🚀 Features

- feat: introduce add-on contract — `papaia-app.yaml` manifest schema, 4 standardised integration seams (network, OIDC, LibreChat-MCP, Ingress)
- feat: full add-on lifecycle in `papaia-ctl` — `addon install`, `addon start`, `addon stop`, `addon remove`, `addon uninstall`
- feat: `papaia-ctl addon check` — pre-upgrade compatibility dry-run against an update candidate (`--target-core=PATH`)
- feat: `ADDON_API` contract-generation window — integer-based compatibility axis independent of the product SemVer (see ADR 0002)
- feat: structural `networks.attach` validation against Core Compose service names
- feat: 3-layer config render (repo base + active add-on fragments + customer overlay)
- feat: per-installation deployment manifest (`deployment.yaml`) as single source of truth for active add-ons and Core profiles
- feat: `papaia-ctl start --addons` / `stop --addons` for full-stack lifecycle including add-ons
- feat: Lean Core — application-specific services removed from Core compose; add-on infrastructure replaces hard-wired service includes
- feat: `papaia-ctl upgrade [--version=X.Y.Z]` — move an installation to a release. Resolves the newest release when no version is given, refuses downgrades, checks active add-ons against the target before anything is touched, takes a restore point, and re-executes itself from the checked-out release so its own render and setup logic applies the change
- feat: release migrations in `tools/migrations/`, run by `upgrade` for every release between the installed and the target version, recorded in `$PAPAIA_CONFIG_DIR/migrations/applied.json` so they never run twice
- feat: `papaia-ctl backup` — hot backup of `PAPAIA_CONFIG_DIR`, all core volumes, and all add-on volumes and data bind mounts into timestamped restore points, with a `backup.yaml` catalogue, `--retention-period-days` pruning, and a result log
- feat: `papaia-ctl restore` — restore a catalogued restore point, with `--list`, `--restore-point`, `--restart-clean` and `--no-restart`. Containers are removed and recreated around the restore, not merely stopped: a stopped container keeps the mount source of every config file it bind-mounts, which the restore replaces
- feat: `PAPAIA_BACKUP_DIR` root variable, settable via `papaia-ctl setup --backup-dir=PATH` and derived as `$PAPAIA_WORKSPACE_DIR/backup`
- feat: `papaia-manager` as an optional core service (profile `manager`) — web UI for the add-on lifecycle plus a dashboard, with native OIDC and role gating via `MANAGER_ADMIN_ROLE` / `MANAGER_USER_ROLE`
- feat: auto-provision Nginx Proxy Manager proxy hosts on start, and `papaia-ctl npm-provision` to run it on demand
- feat: native OIDC for LocalAI, replacing its oauth2-proxy sidecar, gated by the `localai-access` realm role
- feat: select the LocalAI accelerator image variant (CPU / NVIDIA / AMD / Intel / Vulkan) during setup, proposed by a hardware probe of the host

### 🧹 Maintenance

- chore: remove `src/backup-papaia.sh` and `src/restore-papaia.sh`, superseded by the `papaia-ctl` commands
- chore: remove the Homepage service, superseded by papaia-manager, whose dashboard renders from `manager/tiles.yaml`. The add-on contract loses the Homepage seam with it and now has four seams (network, OIDC, LibreChat-MCP, Ingress)
- chore: pin image tags directly in each service's compose file and drop the `*_IMAGE` variables from `src/.env.example`
- chore: bump LocalAI to `v4.7.1`

### 📖 Documentation

- docs: rename and translate architecture specification to `docs/architecture.md` (English)

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v0.8.0...v1.0.0

## [0.8.0] - 2026-06-29

### 🚀 Features

- feat(firecrawl): activate as internal LibreChat scraper (#84)
- feat(mcp-firecrawl): add Firecrawl MCP server to the stack (#86)
- feat(mcp-office-docs): add office-document generation MCP server with minio-backed downloads (#88)
- feat(jinaai): enable jina-reranker-api with env wiring and healthcheck (#89)

### 🧹 Maintenance

- chore: add public-repo hardening files (#78)
- ci(deps): bump hadolint/hadolint-action from 3.1.0 to 3.3.0 (#79)
- ci(deps): bump amannn/action-semantic-pull-request from 5 to 6 (#80)
- ci(deps): bump release-drafter/release-drafter from 6 to 7 (#81)
- ci(deps): bump actions/checkout from 4 to 6 (#82), then from 6 to 7 (#90)
- ci(deps): bump actions/github-script from 7 to 9 (#83)

### 📖 Documentation

- docs: add engineering reference for contributors (#87)

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v0.7.0...v0.8.0

## [0.7.0] - 2026-06-11

### 🚀 Features

- feat: add qdrant-rbac service and LibreChat MCP integration with OIDC token forwarding (#51)
- feat(qdrant-webdav-ingest): add WebDAV → Qdrant ingestion service with MCP interface (#56)
- feat(librechat): optional agents bind-mount from an external directory (#58)
- feat(paperless): make media, export and consume directories configurable (#61)
- feat(paperless): make SSO and login behaviour configurable via .env (#63)
- feat(librechat): optional prompts bind-mount with markdown front matter (#66)
- feat: replace mcp-paperless with oidc-secured paperless-mcp-rbac (#70)

### 🐛 Bug Fixes

- fix(qdrant-rag): consolidate all env vars into root src/.env (#53)
- fix(librechat): defer QdrantRAG MCP init to first per-user call (startup: false) (#54)
- fix: correct qdrant-rbac image name in env example (#72)

### 🛠 Maintenance

- chore: remove doc-rag module from stack (#71)

### 📖 Documentation

- docs: add architecture overview and big-picture diagrams (#59)
- docs: add license and legal documents (#69)
- docs: document v0.7.0 service images in THIRD_PARTY_LICENSES.md (#75, #76)

**Full Changelog**: https://github.com/Fidonis/papaia/compare/v0.6.0...v0.7.0

[Unreleased]: https://github.com/Fidonis/papaia/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Fidonis/papaia/compare/v0.8.0...v1.0.0
[0.8.0]: https://github.com/Fidonis/papaia/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Fidonis/papaia/compare/v0.6.0...v0.7.0
