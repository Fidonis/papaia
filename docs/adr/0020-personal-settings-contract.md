---
adr: 0020
title: Declare personal settings in the manifest, keep the values in each module and render a registry for an own personal area
status: Proposed
date: 2026-11-20
deciders:
  - WilhelmSebastian
tags:
  - addon-contract
  - personal-settings
  - keycloak
  - privacy
  - core
supersedes: null
superseded_by: null
---

# 0020. Declare personal settings in the manifest, keep the values in each module and render a registry for an own personal area

## Context

A person who uses the platform has settings in several places, each with its own
interface or none at all: the notification preferences of the workflow module (channels,
quiet hours, digest, language; replaced as a whole by `PUT`, no protection against lost
updates, no page), the deputies of the workflow module (records with a life cycle, at most
90 days), the settings of the assistant module (name, tone, learning, levels per kind of
action; changed by `PATCH`, an own page), the language of papaia-manager, and the
identity data in Keycloak. Add-ons will bring their own. Nobody can answer "what does
the platform know about me" without asking the data protection officer.

Three findings constrain the answer:

- **Only the module knows its limits.** The assistant offers only levels under the
  organisation's ceiling, the workflow module only the channels the installation has
  switched on. A second place that checks values becomes a second source of truth.
- **The modules read the values in their hot path** — every delivery, every step of a
  conversation. A central store means a network call there, and its failure takes the
  modules down with it.
- **Declarations travel with the software** in this platform: the knowledge map collects
  the `knowledge:` sections of active add-ons and core modules in a render step. The same
  shape fits a description of settings.

## Decision

1. **A manifest section `personal_settings:`** (add-on: `papaia-app.yaml`; core module:
   `personal-settings.yaml` in its directory) declares groups of settings with a closed
   set of field types (`boolean`, `choice`, `multi_choice`, `ordered_multi_choice`,
   `integer`, `text`, `time_range`, `date`, `person`) and collections of records with
   named operations. It holds structure and defaults, never values or secrets. The
   contract — section, JSON Schema, module API, error codes, ETag rules — is
   [docs/personal-settings-contract.md](../personal-settings-contract.md), generation 1.
2. **Every module keeps and checks its own values** and offers a thin module API:
   `GET {base_path}` with values, an ETag and runtime narrowing per group; `PUT` per group
   with `If-Match`; item routes for collections; a summary and an export of the person's
   own data. The area stores nothing.
3. **The core checks and renders.** While the profile `me` is on, every render collects
   the declarations of the active add-ons and of the core modules whose profile is on,
   checks them against the contract (closed types, defaults that fit, plain text within
   80/300 characters, no markup, links or instruction-shaped text, an audience that is a
   Keycloak client of the add-on itself) and writes
   `$PAPAIA_CONFIG_DIR/personal-settings/registry.yaml`. A broken declaration stops the
   render with a named error; one of an unserved generation is left out with a warning.
   The registry is JSON so the standard-library realm sync can read it.
4. **The personal area is its own module**: profile `me`, service `me-web`, image
   `ghcr.io/fidonis/papaia-me` pinned in `src/infra/me/docker-compose.yml`, no database,
   the registry mounted read-only, `setup --me`, a proxy host from `ME_PUBLIC_URL`.
   `me-web` is attachable (`ADDON_API` generation 8), so an add-on's network can be
   reached by the area.
5. **One audience per token.** The area is the confidential client `papaia-me` and
   exchanges the person's token per module for a token with only that module's audience.
   For each audience in the registry the realm sync creates the scope `aud-<audience>`
   (an audience mapper), attaches it as an optional scope of `papaia-me`, and adds the
   client policy `papaia-one-audience-<audience>`: a token exchange that asks for
   that scope together with another managed audience scope is rejected. The caller
   always sends `audience=<audience>` as well: without it Keycloak adds the audiences of
   the realm's default scopes (`account`). Keycloak
   26.7.0 has no executor that counts audiences (checked in its server info); the
   combination of a `grant-type` condition, two `client-scopes` conditions and the
   `reject-request` executor does the job and was run against a local 26.7.0. The area
   checks the issued token as well.
7. **papaia-manager uses the same rule.** While the profile `manager` is on, the sync
   gives `papaia-manager` the optional scope `aud-flow` and standard token exchange: the
   manager exchanges the signed-in administrator's token for one with only the audience
   `flow` to approve a Flow link while an add-on is installed, and refuses any other
   `aud`. The one-audience policies cover it unchanged.
8. **Other modules link to the area through `PERSONAL_SETTINGS_URL`** in the root
   `.env`: `ME_PUBLIC_URL` while the profile `me` is on, empty otherwise, re-derived by
   every `setup`. papaia-manager receives it as `MANAGER_PERSONAL_SETTINGS_URL`; Assist
   is to receive it as `ASSIST_ME_URL` where its compose file is wired — the core has no
   such file yet, so that mapping is carried by the Assist module (`ASSIST_ME_URL:
   ${PERSONAL_SETTINGS_URL:-}`).
6. **Sensitive groups are checked by the module.** A group with `sensitive: true` needs a
   fresh sign-in; the module answers `403 step_up_required` and does not trust the area to
   have asked.

### Amendment of 20.11.2026: the contract as the modules build it

Aligning papaia Flow, Assist and the area on the contract settled what generation 1 left
open. [docs/personal-settings-contract.md](../personal-settings-contract.md) states it and
is the single truth; the modules refer to it.

9. **Write bodies are plain.** `PUT {base_path}/{group}` takes the plain object of values,
   an item is created from the plain object of its fields, and error pointers point into
   that body (`/digest`). A `person` is written as its id string and read as
   `{id, display}`. Both modules took this shape already; a wrapper (`{"values": …}`)
   would have added nothing but a second shape.
10. **A person is chosen from the module.** `GET {base_path}/{group}/persons?q=` (at least
    two characters, at most 20 results of exactly `{id, display}`, only persons the caller
    may name for that purpose, rate-bounded with `429 rate_limited`). The module knows who
    may be named (Flow: the rules of delegation); the area holds no directory.
11. **Option values are typed**: a string, an integer or a boolean, one type per field; the
    area writes a value back in that type (Assist's levels are integers). The string
    grammar allows `/` so folders can be offered (`/purchasing`).
12. **Titles are required where a person reads them**: runtime options of a field declared
    `options: runtime` carry `title{de,en}`, and every summary category carries
    `title{de,en}`; runtime entries are objects, never bare values.
13. **Errors keep the module's catalogue.** A module that answers problem details or its
    own codes adds `contract_code`; entries of `422` carry contract codes and may add
    `module_code` and `message`.
14. **The registry names what is not connected**: `not_connected` lists the chat front end,
    the model gateway, the identity provider and, while its profile is on, papaia-manager,
    so the overview of a person's data never claims to be complete.
15. **One declaration per module, where it is installed.** papaia Flow is the add-on
    `papaia-flow`: it declares in its manifest under its add-on name, and the core file
    `src/flow/personal-settings.yaml` is gone (no profile `flow` exists to read it). Its
    Keycloak client `flow` is created by its own action `idp-setup`, not by a fragment, so
    the core lists it in `ADDON_REALM_CLIENTS`: `papaia-flow` may name `flow`, and no other
    add-on can, not even with a fragment of that name. Assist is the core module of the
    profile `assist` with the fixed audience `assist-api` and declares only in
    `src/ai/assist/personal-settings.yaml`, now with the groups and integer levels it
    serves.
16. **Fresh sign-in is `auth_time`.** Measured against Keycloak 26.7.0 (report in
    `papaia-me`, `docs/messung-auth-time-token-austausch.md`): the standard token exchange
    keeps `auth_time`, and `prompt=login&max_age=0` renews it. No mapper and no `acr` level
    are needed; `acr` stays `"1"` and is not used.
17. **Transport to the modules.** The area checks every https certificate against the
    platform CA and the public CA files in `personal-settings/module-ca/<module>.pem`,
    which a module with its own CA writes (Flow from its certificate setup). Plain http
    is used only where declared and never under `PAPAIA_SECURITY_PROFILE=kritis`.
    papaia Flow attaches `me-web` (`requires.addon_api: 8`).
18. **Errors before a route's own checks carry contract codes as well** (`401
    unauthorized`, `400 malformed_request`, and `409 conflict` for an `Idempotency-Key`
    used for another request); a created item answers with `Location`; `display` is a
    name, never an e-mail address, else `Person <first 8 characters of the id>`.

### Amendment of 20.11.2026: review of the area and the render

19. **An audience belongs to one owner.** An add-on that registered a fragment with the
    client ID `papaia-manager` (or `assist-api`, `account` …) could make the area hand a
    token for that service to the add-on's own service. The render therefore refuses as an
    add-on's audience every client of the core (realm template, fixed audiences of the
    core modules, Keycloak's built-in clients) and every client that another active
    add-on's fragment defines too; the audience must be a client that only the add-on's
    own fragment defines. `ADDON_REALM_CLIENTS` stays for papaia Flow and is bound to the
    add-on `papaia-flow` alone. The registry never holds one audience twice.
20. **Declared patterns come from a safe subset.** Python's engine backtracks; a plausible
    pattern such as `([A-Za-z]+ ?)+` blocks the area's single worker for seconds on 25
    characters. A non-backtracking engine would have been a new native dependency of the
    area and a second dialect for module authors; the core instead renders only a subset
    whose number of ways to match a text of the field's `max_length` is bounded (no
    nested loops, no alternatives under a loop, no backreferences or lookaround, at most
    1,000,000 ways), and the area checks the same rules again and matches only texts within
    `max_length`. The rules are in the contract, section 1.
21. **Endpoint rules are the area's.** `service` is a DNS label and paths have no `~` and
    no segment starting with a dot; the render no longer passes what the area refuses.
22. **One audience also at sign-in and refresh.** The one-audience policies name the
    grant types `token-exchange`, `authorization_code` and `refresh_token`. Run against a
    local Keycloak 26.7.0 with the sync's own code: an authorization request of
    `papaia-me` for `aud-flow aud-assist-api` is refused before the sign-in, a refresh of a
    grant with both made before the policy is refused, single scopes and the plain sign-in
    keep working. Without the explicit grant types Keycloak already refused the code grant
    at the token endpoint; the explicit form does not rely on that.
23. **Collection operations are those of contract v1.** The render and the schema accept
    only `create`, `end` and `renew`, the three the area offers; a declaration with another
    operation used to render and then failed in the area. A further operation needs a new
    contract version.

## Consequences

- **Positive**: one place for the person, without a central profile of everyone's
  preferences; a failed area leaves every module working; add-ons and core modules use the
  same contract; lost updates are caught by the ETag; the realm never issues the area a
  token for two modules.
- **Positive**: the declaration is foreign text shown to every person; the render refuses
  what a page should never show instead of relying on escaping alone.
- **Negative**: each module needs the contract routes and a self-service export; the
  workflow and assistant modules have neither today.
- **Negative**: one more image, client and proxy host. The realm sync manages scopes,
  optional `aud-*` scopes of `papaia-me` and `papaia-manager` and policies with the
  prefix `papaia-one-audience-` as its own and prunes the ones no longer wanted;
  scopes themselves are never deleted.
- **Neutral**: Keycloak's audience mappers name a client; the audience of a module
  (`flow`, `assist-api`) only takes effect once its client exists in the realm, which
  comes with that module's profile or, for papaia Flow, with its action `idp-setup`.
- **Negative**: a new add-on whose client comes from its own realm setup needs an entry
  in `ADDON_REALM_CLIENTS` before it can declare personal settings; a fragment is the
  way that needs no change of the core.
- **Negative**: a module author cannot use every regular expression in `pattern`; a
  pattern such as `(\d+\.){3}\d+` has to be written without the loop over a group with a
  quantifier (`\d+\.\d+\.\d+\.\d+`).
- **Neutral**: the core has no platform-wide `PAPAIA_SECURITY_PROFILE` in its own
  configuration yet; `me-web` reads it with the default `standard`.

## Alternatives considered

- **A central store of all settings in the area** — the modules would read it in their hot
  path or keep a copy; limits would be checked twice; the area's failure would stop
  notifications and the assistant; one place would hold everyone's preferences across
  modules.
- **The area inside papaia-manager** — the manager mounts the Docker socket; every person
  would use a service with root-equivalent rights on the host every day, and the manager
  does not run everywhere.
- **Free-form forms (HTML or a UI schema from the module)** — a foreign module could
  bring markup and script to a page every person sees; a closed set of field types is
  enough for the settings that exist.
- **A token with all module audiences** — one leaked token would open every module; and
  Keycloak issues several audiences when asked, so the realm has to forbid it.
- **Checking the declaration only in the area** — a broken or hostile declaration would
  reach a running area; the render step already sees every manifest and is where the
  knowledge map checks its declarations.

## References

- [docs/personal-settings-contract.md](../personal-settings-contract.md)
- [ADR 0002](0002-addon-core-compatibility-gating.md) — contract generations
- [ADR 0006](0006-manage-accounts-with-the-signed-in-users-token.md) — tokens of the signed-in person
- RFC 8693 (token exchange), RFC 9110 (conditional requests), RFC 6901 (JSON Pointer)
