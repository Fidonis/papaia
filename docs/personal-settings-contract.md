# Personal settings — contract version 1

Every person who uses the platform sees and changes their own settings in one place,
the personal area (core profile `me`, service `me-web`). The area stores nothing: each
module keeps and checks the values of its own settings and offers them over the module
API below. The area reads the structure of every module from a registry the core
renders, asks each module for the values with a token meant for that module only, and
shows one form per group.

This document is the binding description of version 1. The decision and the
alternatives are in [ADR 0020](adr/0020-personal-settings-contract.md).

| Part | Where |
|---|---|
| Declaration of a module (`personal_settings:`) | exactly one per module, where the module is installed: an add-on in its `papaia-app.yaml` (papaia Flow: add-on `papaia-flow`), a core module in `personal-settings.yaml` in its directory (Assist: `src/ai/assist/`) |
| JSON Schema of the declaration | [`tools/schemas/personal-settings.schema.json`](../tools/schemas/personal-settings.schema.json) |
| Check and render | `tools/lib/personal_settings.py`, on every render while the profile `me` is on |
| Rendered registry | `$PAPAIA_CONFIG_DIR/personal-settings/registry.yaml` |
| Token exchange per module | Keycloak client `papaia-me`, scopes `aud-<audience>`, client policies `papaia-one-audience-*` |
| Link to the area for other modules | `PERSONAL_SETTINGS_URL` in the root `.env` (empty while `me` is off) |

## 1. The declaration

```yaml
personal_settings:
  api: 1                                # contract generation of the section
  module: papaia-flow                   # unique; for an add-on its name
  title: {de: "Abläufe", en: "Workflows"}
  endpoint:
    service: flow-api                   # Compose service (a DNS label), reachable from me-web
    scheme: https                       # http (default) | https
    port: 8444
    base_path: /api/v1/me/settings      # the module API, section 3
    audience: flow                      # Keycloak client of the module
  data:
    summary: /api/v1/me/data/summary    # section 3.5
    export: /api/v1/me/data/export      # section 3.5
    erasure: request                    # none | self | request
  groups:
    - id: notifications
      title: {de: "Benachrichtigungen", en: "Notifications"}
      description: {de: "…", en: "…"}   # optional
      data_class: personal              # public | internal | confidential | personal | special
      sensitive: false                  # true: fresh sign-in before a change is stored
      settings:                         # kind: settings (the default)
        - key: digest
          type: choice
          default: "off"
          options:
            - {value: "off", title: {de: "Einzeln", en: "One by one"}}
            - {value: "daily", title: {de: "Einmal täglich", en: "Daily digest"}}
          title: {de: "Hinweise zur Information", en: "Information notices"}
    - id: deputies
      kind: collection                  # records with a life cycle
      sensitive: true
      title: {de: "Vertretung", en: "Deputy"}
      data_class: personal
      item:
        fields:
          - {key: delegate, type: person, title: {de: "Vertreten durch", en: "Deputy"}}
          - {key: until, type: date, max_days: 90, title: {de: "Bis", en: "Until"}}
      operations: [create, end, renew]
```

### 1.1 Field types

The set is closed. A declaration with any other type is refused.

| `type` | Own properties | Value in the module API |
|---|---|---|
| `boolean` | `default` | `true` / `false` |
| `choice` | `options` (required), `default` | one option value, in the type of the options |
| `multi_choice` | `options` (required), `default` (list) | list of option values, no duplicates, order irrelevant |
| `ordered_multi_choice` | `options` (required), `default` (list) | list of option values, no duplicates, order is the person's priority |
| `integer` | `min`, `max` (both required), `default` | integer |
| `text` | `max_length` (1..1000, required), `pattern`, `default` | string, plain text |
| `time_range` | `default` | `{"start": "HH:MM", "end": "HH:MM"}`, 24 h; `end` before `start` crosses midnight |
| `date` | `max_days` (1..3660) | `"YYYY-MM-DD"`, from today to today + `max_days` |
| `person` | — | write: the id as a string, `"<sub>"`; read: `{"id": "<sub>", "display": "<name>"}` |

Every field has `key` (`^[a-z][a-z0-9_]{0,63}$`, stable), `title` and optionally `hint`
and `replaces` (the key it was renamed from). `options` is either `runtime` or a list of
1 to 64 `{value, title}`. An option value is a string matching
`^[a-z0-9/][a-z0-9_./-]{0,254}$`, an integer (within ±(2^53 − 1)) or a boolean; all options
of one field have the same type, and a default has that type too. JSON keeps `1`, `true`
and `"1"` apart, and so does every party: the area writes a value back in the type the
module declared or offered (Assist's levels are the integers 0 to 5). A `person` is always
chosen from the module's own list of persons (section 3.3), never typed in.

### 1.2 Rules the render step checks

- **Plain text only.** Titles (also of options) at most 80, hints and descriptions at
  most 300 characters per language. At least one of `de` and `en`; a missing language
  falls back to the other. Control characters are removed. Markup, links (`scheme://`,
  `www.`, `javascript:`), Markdown links, model control tokens, text shaped like an
  instruction to a model, zero-width and direction-changing characters are refused.
- **Defaults fit**: a default is among the options, within `min`..`max`, at most
  `max_length` long and matches `pattern`; `pattern` compiles; `min` ≤ `max`.
- **Patterns of a safe subset.** The area matches a person's text against `pattern` on
  every save (always as a full match), and the engine backtracks. A pattern is therefore
  rendered only from this subset: literals, `.`, classes `[...]`, the escapes `\d \D \w
  \W \s \S \b \B \A \Z \n \t \r \f \v` and escaped punctuation, anchors `^ $`, groups
  `(...)` and `(?:...)`, alternatives `|`, and the quantifiers `* + ? {m} {m,} {m,n}`
  (also lazy) with bounds up to 1000. Refused: backreferences, lookaround, inline flags,
  conditionals, named groups, possessive quantifiers, an unescaped `{`, `}` or nested `[`,
  a loop (a quantifier that may repeat more than once) over a part that holds a quantifier
  or an alternative, and a pattern with more than 1,000,000 ways to match a text of the
  field's `max_length` (a loop counts once per possible repetition count, an optional part
  and every alternative add their own). `([A-Za-z]+ ?)+` is refused, `^(https://\S+)?$`
  and `^[^@]*$` are rendered. The area checks the same rules and refuses a value against a
  pattern outside them.
- **Endpoint names the area can dial**: `service` is a DNS label (lower-case letters,
  digits, inner hyphens, at most 63 characters; no dot, no underscore); `base_path`,
  `data.summary` and `data.export` are absolute paths of segments of letters, digits, `_`,
  `-` and `.`, where no segment starts with a dot (no `~`, no `..`, no trailing slash).
- **Operations of contract v1**: a collection declares one or more of `create`, `end`
  and `renew`, each once; any other name is refused. The area offers exactly these three,
  so a further operation comes with a new contract version, not with a declaration.
- **Unique**: group IDs per module, keys per group or item, option values per field,
  module names across the installation.
- **Audience**: an add-on may only name a client of its own: one that its own Keycloak
  fragments (`integration.keycloak.clients`) and no other active add-on's fragments define,
  or one its own realm setup creates and the core knows by name (`ADDON_REALM_CLIENTS` in
  `tools/lib/personal_settings.py`, bound to the add-on of that name: only `flow` of the
  add-on `papaia-flow`, created by its action `idp-setup` and already the audience
  papaia-manager exchanges for). Never a client of the core, even through a fragment of the
  add-on: the clients of the realm template (`papaia-me`, `papaia-manager`, `librechat`
  …), the fixed audiences of the core modules (`assist-api`, also while its profile is
  off) and the clients Keycloak creates in every realm (`account`, `account-console`,
  `admin-cli`, `broker`, `realm-management`, `security-admin-console`). A token for such a
  client must never reach an add-on's service. Without a client of its own an add-on
  cannot use the section. A core module only the audience the core gives it (`assist-api`
  for Assist). `module` of an add-on is its `name`. No audience appears twice in the
  registry.
- **One declaration per module**: papaia Flow is installed as the add-on `papaia-flow`
  and declares in its manifest; Assist is a core module (profile `assist`) and declares in
  `src/ai/assist/personal-settings.yaml`. A module name declared twice stops the render.
- **Only active software**: declarations of add-ons that are not active and of core
  modules whose profile is off are not rendered.
- **Generation**: a declaration whose `api` the core does not serve is left out with a
  warning; every other violation stops the render with an error that names the module
  and the place in the section.
- No values and no secrets: a declaration holds structure and defaults only.

### 1.3 The registry

`registry.yaml` is JSON (and therefore YAML), deterministic, without a time stamp:

```json
{
  "registry": 1,
  "api": {"min": 1, "current": 1},
  "digest": "sha256:<over modules>",
  "modules": [
    {"api": 1, "module": "assist", "title": {...}, "endpoint": {...}, "data": {...},
     "groups": [...], "declared_by": "module:assist"}
  ],
  "not_connected": [
    {"id": "chat", "title": {"de": "Chat", "en": "Chat"}, "hint": {"de": "…", "en": "…"}}
  ]
}
```

Modules are sorted by name. Each is the checked declaration with the defaults filled in
(`endpoint.scheme`, `kind`, `sensitive`) and `declared_by` (`module:<profile>` or
`addon:<name>@<version>`). The area mounts the directory read-only and reads nothing else
about the modules.

`not_connected` lists the platform services that keep personal data but declare no
personal settings, so "what the platform knows about me" never claims a completeness it
does not have. The core writes it on every render, in a fixed order: `chat` (the chat
front end: conversations and uploads), `model-gateway` (usage data of the language
models), `identity` (the identity provider: name, mail, password, second factor,
sessions) and, while its profile is on, `manager` (the language chosen there). Each entry
is `{id, title, hint}` with plain text in `de` and `en` (title ≤ 80, hint ≤ 300). It is not
part of `digest`.

## 2. Sign-in and tokens

- The area is the confidential client `papaia-me` (authorization code with PKCE S256).
  It works as the backend of its pages: no token reaches the browser.
- For every call to a module it exchanges the person's token (Standard Token Exchange,
  `urn:ietf:params:oauth:grant-type:token-exchange`) with `scope=aud-<audience>` and
  `audience=<audience>` for a token with exactly that one audience, at most 300 s. The
  scope `aud-<audience>` is an optional scope of `papaia-me` and the only way the
  audience becomes available.
- Keycloak 26.7.0 issues a token with two audiences when two are asked for. The realm
  therefore carries one client policy per audience, `papaia-one-audience-<audience>`:
  a token exchange that asks for `aud-<audience>` together with any other managed
  `aud-*` scope is refused (`400 invalid_request`, "Request not allowed"). The same holds
  for the sign-in and its refresh (`grant-type` condition with `authorization_code` and
  `refresh_token` as well): an authorization request for two `aud-*` scopes is refused
  before the sign-in (`error=invalid_request`), and a grant with two that was made before
  the policy existed is not refreshed (run against a local Keycloak 26.7.0 on 20.11.2026
  with the realm sync's own code). The policies
  work for every client that exchanges this way; besides `papaia-me` that is
  `papaia-manager`, whose only scope is `aud-flow` (approving a Flow link while an add-on
  is installed).
- The `audience` parameter is **required**, not optional: without it Keycloak adds the
  audiences of the realm's default scopes (`account` for a person with the default
  roles), so `scope=aud-flow` alone yields `aud: ["flow", "account"]`; with
  `audience=flow` the token carries `flow` only. The policies prevent two module
  audiences, the caller's `audience` parameter and the module's check prevent the rest.
  The area
  also checks the issued token before use: exactly one `aud` equal to the module's
  audience, `azp=papaia-me`, `sub` of the signed-in person, lifetime ≤ 300 s.
- The module checks signature, issuer, audience and expiry as for any other caller, and
  takes the person from `sub`, never from the request. It may also check `azp`.
- **Fresh sign-in** for a group with `sensitive: true` is checked by the module, not by the
  area: unless the exchanged token's `auth_time` is at most 300 s old, a write that needs it
  answers `403 {"code": "step_up_required", "max_age": 300}` (or the module's own code with
  `"contract_code": "step_up_required"`). The area then signs the person in again
  (`prompt=login`, `max_age=0`), exchanges the new token and repeats the request once. A
  module may decide which writes of a sensitive group need it (raising a level does,
  lowering it does not).
- Measured against Keycloak 26.7.0 (20.11.2026, report in the `papaia-me` repository,
  `docs/messung-auth-time-token-austausch.md`): the standard token exchange keeps
  `auth_time` unchanged in the exchanged token; after `prompt=login&max_age=0` the new
  sign-in carries a newer `auth_time`, and so does the token exchanged from it. `acr` stays
  `"1"` and says nothing about freshness, so modules check `auth_time` and nothing needs a
  mapper. Not measured: an external identity provider or a second factor.

## 3. Module API, version 1

All bodies are JSON (`Content-Type: application/json`, UTF-8). Every response carries
`Cache-Control: no-store`. Answers larger than 256 KiB, or slower than 2 s, are treated
by the area as "module not reachable". Paths are relative to the module's service.

**Transport.** The area calls `<scheme>://<service>:<port><base_path>` exactly as declared
and never follows a redirect. With `scheme: https` it checks certificate and host name
against the platform CA (`SSL_CERT_FILE` of `me-web`, `/certs/local-ca.crt`) and the
public CA files modules place in `$PAPAIA_CONFIG_DIR/personal-settings/module-ca/`, one
`<module>.pem` each, certificates only (mounted read-only at `/registry/module-ca/`). A
module whose endpoint is signed by its own CA (Flow: `flow-api`) writes that file itself.
`scheme: http` is used only as declared and never under the security profile `kritis`
(`PAPAIA_SECURITY_PROFILE`; the area may set itself stricter, never laxer): there the
module is shown as not reachable. An add-on whose service the area must reach lists
`me-web` under `networks.attach` (`requires.addon_api: 8`).

### 3.1 Read all groups — `GET {base_path}`

```json
{
  "contract": 1,
  "module": "papaia-flow",
  "groups": {
    "notifications": {
      "etag": "\"n-3\"",
      "values": {
        "channels": ["mail", "chat"],
        "mute_info": false,
        "quiet_hours": true,
        "digest": "daily",
        "locale": "de"
      },
      "runtime": {
        "options": {
          "channels": [
            {"value": "mail", "title": {"de": "E-Mail", "en": "Mail"}},
            {"value": "chat", "title": {"de": "Chat der Assistenz", "en": "Assistant chat"}}
          ]
        },
        "bounds": {}
      }
    },
    "deputies": {
      "etag": "\"d-7\"",
      "count": 1,
      "runtime": {"options": {"folder": [{"value": "/purchasing",
                                          "title": {"de": "/purchasing", "en": "/purchasing"}}]},
                  "bounds": {"until": {"max_days": 90}}}
    }
  }
}
```

- `contract` is the generation of the module API (1); the area serves a window like the
  registry's `api`. A module outside the window is shown read-only. `module` is optional
  and not read by the area.
- A settings group carries `etag`, `values` (every declared key, the module's default
  where the person chose nothing) and optionally `runtime`. A collection group carries
  `etag`, `count` and optionally `runtime`; its items are read separately (3.3).
- A group the person may not use is left out. A module that answers `403` on this
  request is not shown at all; the area derives no rights itself.

**Runtime may only narrow** what the declaration allows; the area drops any runtime
entry that would widen it and never offers it:

| `runtime` entry | Shape | Rule |
|---|---|---|
| `options.<key>` | list of `{value, title?}` objects, never bare values | for declared options: a subset of the declared values in their declared type (the declared titles are used; a `title` sent along is ignored); for `options: runtime`: 0..64 entries, each with a valid value and a `title` `{de?, en?}` (≤ 80, plain text) — required, the only source of the options |
| `options.<key>` (boolean) | subset of `[{"value": false}, {"value": true}]` | fixes a boolean to the values left; with one value the field is shown locked |
| `bounds.<key>` (integer) | `{"min": n, "max": m}` | within the declared `min`..`max` |
| `bounds.<key>` (text) | `{"max_length": n}` | at most the declared `max_length` |
| `bounds.<key>` (date) | `{"max_days": n}` | at most the declared `max_days` |

### 3.2 Replace one group — `PUT {base_path}/{group}`

Request (header `If-Match: "n-3"`); the body is the plain object of values:

```json
{"channels": ["chat"], "mute_info": false, "quiet_hours": true,
 "digest": "off", "locale": "de"}
```

The body holds the whole group, every declared key; the module replaces the group as a
whole. A key that is not declared is `unknown_key`. Answer `200` (optionally with
`runtime`, as in 3.1):

```json
{"etag": "\"n-4\"", "values": {"channels": ["chat"], "mute_info": false,
                               "quiet_hours": true, "digest": "off", "locale": "de"}}
```

with the new ETag also in the `ETag` header.

### 3.3 Collections

Only for groups with `kind: collection`.

`GET {base_path}/{group}/items` → `200`:

```json
{
  "etag": "\"d-7\"",
  "items": [
    {
      "id": "dlg-42",
      "etag": "\"dlg-42-2\"",
      "state": "active",
      "fields": {"delegate": {"id": "4c0a…", "display": "Bernd Muster"},
                 "folder": "/purchasing", "until": "2026-12-31"},
      "operations": ["end", "renew"]
    }
  ]
}
```

- `id` is a string matching `^[A-Za-z0-9_-]{1,64}$`; `state` is `active`, `ended` or
  `expired`; `fields` holds the declared item fields (a `person` as `{id, display}`);
  `operations` lists the declared operations this item allows now (never `create`). A
  module may add keys of its own to an item (Flow: `role`); the area ignores them.
- `POST {base_path}/{group}/items` with the plain object of fields creates an item when
  `create` is declared, a person as its id string:

  ```json
  {"delegate": "4c0a…", "folder": "/purchasing", "until": "2026-12-31"}
  ```

  Answer `201` with the item and `Location: {base_path}/{group}/items/{id}` (a path; also
  when an `Idempotency-Key` replays the first answer). The module may require an
  `Idempotency-Key` header (Flow does, for every writing operation); the area always sends
  one per rendered form, and a repeated request answers with the first item.
- `POST {base_path}/{group}/items/{id}/{operation}` (`end` or `renew`) with header `If-Match: <item etag>`,
  `Idempotency-Key`, and an optional plain object of fields (for example `{"until":
  "2027-01-31"}` for `renew`): `200` (or `201` when the operation makes a new item, as a
  renewal in Flow does) with the item.

#### Choosing a person — `GET {base_path}/{group}/persons?q=<text>`

For every group with a field of type `person` the module answers which persons the caller
may name there. The area offers nothing else: a person is never typed in.

```json
{"persons": [{"id": "4c0a…", "display": "Bernd Muster"}]}
```

- `q` is at least 2 characters after trimming (else `400 malformed_request`) and at most
  64; the module matches it against the display name, case-insensitive. No other
  parameter is read.
- At most 20 entries, sorted by `display`; no `etag`.
- Only persons the caller may name for that group's purpose under the module's own rules
  (Flow, `deputies`: active persons of its directory, never the caller, the rules of
  delegation). The caller's own rights decide, never the request.
- Each entry is exactly `{id, display}`: no e-mail address and no other attribute.
  `display` is plain text of at most 80 characters: the directory's display name, else
  given and family name, never an e-mail address or a login name; without a name it is
  `Person <first 8 characters of the id>`. The same `display` names a person in items
  (`{id, display}`).
- Rate-bounded per person: beyond the module's bound (at most 30 searches a minute is the
  default) it answers `429 {"code": "rate_limited"}` with `Retry-After`.
- A group without a `person` field answers `404 unknown_group`.

### 3.4 Errors

Every error body is a JSON object with the contract's code below. A module whose errors
carry its own catalogue code in `code` (problem details, RFC 9457, as in Flow; or its own
catalogue as in Assist) puts the contract's code in `contract_code`; the area reads
`contract_code` first, then `code`. The area translates contract codes from its own
catalogue; a `message` from the module (plain text, ≤ 300 characters) is shown only as text
and never interpreted.

| Status | `code` | Meaning |
|---|---|---|
| `400` | `malformed_request` | not JSON, or not the shape above; a required `Idempotency-Key` missing |
| `401` | `unauthorized` | token missing, invalid or not for this audience |
| `403` | `forbidden` | the person may not use this group or item |
| `403` | `step_up_required` | sensitive group: a fresh sign-in is needed; `max_age` (s) names how fresh |
| `405` | `not_allowed_now` | `PUT` on a collection group |
| `404` | `unknown_group`, `unknown_item`, `unknown_operation` | |
| `409` | `not_allowed_now` | the operation does not fit the item's state |
| `409` | `conflict` | the `Idempotency-Key` was used for another request, or its first request still runs |
| `412` | `stale` | the ETag in `If-Match` is not the current one; `etag` names the current one |
| `428` | `precondition_required` | `If-Match` is missing |
| `422` | `invalid` | values do not pass the module's checks; `errors` lists them |
| `429` | `rate_limited` | too many requests of this person (person search); `Retry-After` says when |

```json
{"code": "invalid",
 "errors": [{"pointer": "/digest", "code": "not_an_option"},
            {"pointer": "/channels/1", "code": "duplicate"}]}
```

`pointer` is a JSON Pointer (RFC 6901) into the plain request body (`/digest`,
`/channels/1`, `/until`). `code` is one of the contract's codes below; a module may add its
own code as `module_code` and a plain-text `message`. Codes of an entry:

| `code` | For |
|---|---|
| `required` | a declared key is missing |
| `unknown_key` | a key that is not declared |
| `wrong_type` | the value has the wrong JSON type |
| `not_an_option` | not among the (runtime) options |
| `duplicate` | a value twice in a list |
| `out_of_range` | integer outside the (runtime) bounds |
| `too_long` | text longer than the (runtime) `max_length` |
| `pattern_mismatch` | text does not match `pattern` |
| `invalid_time` | not `HH:MM` |
| `invalid_date` | not a date, in the past or beyond `max_days` |
| `unknown_person` | no such person in the directory |
| `not_allowed` | the module's own rule refuses the value (a ceiling of the organisation, a name that is taken …); `message` may say why |

### 3.5 What the platform knows about me

`GET {data.summary}` → `200`, categories with counts, never content. `categories` is a
list; every category has `id`, a `title` in `de` and `en` (plain text, ≤ 80 — required: the
area shows titles, never table or key names), `count`, and optionally `data_class` and
`truncated` (the count reached the module's bound):

```json
{"contract": 1,
 "categories": [
   {"id": "notification_preferences", "title": {"de": "Benachrichtigungen", "en": "Notifications"},
    "count": 1, "data_class": "personal"},
   {"id": "deliveries", "title": {"de": "Zugestellte Nachrichten", "en": "Delivered messages"},
    "count": 214, "data_class": "personal"}
 ],
 "erasure": "request"}
```

`GET {data.export}` → `200`, the person's own data as one JSON object, machine-readable,
built on every call and never stored. Its shape is the module's own; the area does not
interpret it and puts it into the download as it came. It should name the module and the
time it was built, for example:

```json
{"module": "papaia-flow", "generated_at": "2026-11-20T09:00:00Z", "...": "module specific"}
```

Both answer only about the person in the token. `erasure` repeats the declaration:
`self` (the module offers deletion to the person in its own API or page), `request` (a
request to the data protection officer), `none`. The area deletes nothing itself.

### 3.6 ETag rules

- One strong ETag (RFC 9110, a quoted string of at most 128 characters) per group, and one
  per collection item.
- It changes whenever a value of the group changes, by whatever route (the area, the
  module's own page, an administrator). It is opaque: the area only compares it and
  never derives anything from it, and the module does not encode values in it.
- `PUT` and item operations require `If-Match`; without it the module answers `428`, with
  an old one `412` and nothing is changed. `If-Match: *` is not accepted, so every write
  follows a read.
- The area's "undo" writes the previous values with the current ETag; if another change
  came in between, that is a normal `412`.

## 4. Versions

- `api` (declaration) and `contract` (module API) count the same generation. A core serves
  the window `[min..current]` of `personal_settings.API_MIN`/`API_CURRENT`.
- **Additive** (a new field type, a new optional property): `current += 1`. An older area
  shows a group with an unknown type read-only with a link into the module.
- **Breaking**: `min` rises; a module outside the window is shown read-only.
- Keys are stable; a renamed key names the old one in `replaces`.
- A core without this contract ignores the section (unknown manifest key); the add-on
  installs there without personal settings. An add-on needs `requires.addon_api: 8` only
  when it attaches `me-web` (`networks.attach: [me-web]`) so the area can reach its API.
