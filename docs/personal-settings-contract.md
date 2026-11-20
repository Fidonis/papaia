# Personal settings — contract version 1

Every person who uses the platform sees and changes their own settings in one place,
the personal area (core profile `me`, service `me-web`). The area stores nothing: each
module keeps and checks the values of its own settings and offers them over the module
API below. The area reads the structure of every module from a registry the core
renders, asks each module for the values with a token meant for that module only, and
shows one form per group.

This document is the binding description of version 1. The decision and the
alternatives are in [ADR 0015](adr/0015-personal-settings-contract.md).

| Part | Where |
|---|---|
| Declaration of a module (`personal_settings:`) | add-on: `papaia-app.yaml`; core module: `personal-settings.yaml` in its directory (`src/flow/`, `src/ai/assist/`) |
| JSON Schema of the declaration | [`tools/schemas/personal-settings.schema.json`](../tools/schemas/personal-settings.schema.json) |
| Check and render | `tools/lib/personal_settings.py`, on every render while the profile `me` is on |
| Rendered registry | `$PAPAIA_CONFIG_DIR/personal-settings/registry.yaml` |
| Token exchange per module | Keycloak client `papaia-me`, scopes `aud-<audience>`, client policies `papaia-me-one-audience-*` |

## 1. The declaration

```yaml
personal_settings:
  api: 1                                # contract generation of the section
  module: flow                          # unique; for an add-on its name
  title: {de: "Abläufe", en: "Workflows"}
  endpoint:
    service: flow-api                   # Compose service, reachable from me-web
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
| `choice` | `options` (required), `default` | one option value (string) |
| `multi_choice` | `options` (required), `default` (list) | list of option values, no duplicates, order irrelevant |
| `ordered_multi_choice` | `options` (required), `default` (list) | list of option values, no duplicates, order is the person's priority |
| `integer` | `min`, `max` (both required), `default` | integer |
| `text` | `max_length` (1..1000, required), `pattern`, `default` | string, plain text |
| `time_range` | `default` | `{"start": "HH:MM", "end": "HH:MM"}`, 24 h; `end` before `start` crosses midnight |
| `date` | `max_days` (1..3660) | `"YYYY-MM-DD"`, from today to today + `max_days` |
| `person` | — | write: `{"id": "<sub>"}`; read: `{"id": "<sub>", "display": "<name>"}` |

Every field has `key` (`^[a-z][a-z0-9_]{0,63}$`, stable), `title` and optionally `hint`
and `replaces` (the key it was renamed from). `options` is either `runtime` or a list of
1 to 64 `{value, title}` with `value` matching `^[a-z0-9][a-z0-9_.-]{0,63}$`. A `person`
is always chosen from the directory, never typed in.

### 1.2 Rules the render step checks

- **Plain text only.** Titles (also of options) at most 80, hints and descriptions at
  most 300 characters per language. At least one of `de` and `en`; a missing language
  falls back to the other. Control characters are removed. Markup, links (`scheme://`,
  `www.`, `javascript:`), Markdown links, model control tokens, text shaped like an
  instruction to a model, zero-width and direction-changing characters are refused.
- **Defaults fit**: a default is among the options, within `min`..`max`, at most
  `max_length` long and matches `pattern`; `pattern` compiles; `min` ≤ `max`.
- **Unique**: group IDs per module, keys per group or item, option values per field,
  module names across the installation.
- **Audience**: an add-on may only name one of the clients it registers itself
  (`integration.keycloak.clients`); without a client of its own it cannot use the
  section. A core module only the audience the core gives it (`flow` for Flow,
  `assist-api` for Assist). `module` of an add-on is its `name`.
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
    {"api": 1, "module": "flow", "title": {...}, "endpoint": {...}, "data": {...},
     "groups": [...], "declared_by": "module:flow"}
  ]
}
```

Modules are sorted by name. Each is the checked declaration with the defaults filled in
(`endpoint.scheme`, `kind`, `sensitive`) and `declared_by` (`module:<profile>` or
`addon:<name>@<version>`). The area mounts the directory read-only and reads nothing else
about the modules.

## 2. Sign-in and tokens

- The area is the confidential client `papaia-me` (authorization code with PKCE S256).
  It works as the backend of its pages: no token reaches the browser.
- For every call to a module it exchanges the person's token (Standard Token Exchange,
  `urn:ietf:params:oauth:grant-type:token-exchange`) with `scope=aud-<audience>` and
  `audience=<audience>` for a token with exactly that one audience, at most 300 s. The
  scope `aud-<audience>` is an optional scope of `papaia-me` and the only way the
  audience becomes available.
- Keycloak 26.7.0 issues a token with two audiences when two are asked for. The realm
  therefore carries one client policy per audience, `papaia-me-one-audience-<audience>`:
  a token exchange that asks for `aud-<audience>` together with any other `aud-*` scope
  of the registry is refused (`400 invalid_request`, "Request not allowed"). The area
  also checks the issued token before use: exactly one `aud` equal to the module's
  audience, `azp=papaia-me`, `sub` of the signed-in person, lifetime ≤ 300 s.
- The module checks signature, issuer, audience and expiry as for any other caller, and
  takes the person from `sub`, never from the request. It may also check `azp`.
- **Fresh sign-in** for a group with `sensitive: true` is checked by the module, not by the
  area: unless `auth_time` is at most 300 s old (or the module accepts an `acr` value it
  names), a write answers `403 {"code": "step_up_required", "max_age": 300}`. The area then
  signs the person in again (`prompt=login`, `max_age=0`) and repeats the request once.

## 3. Module API, version 1

All bodies are JSON (`Content-Type: application/json`, UTF-8). Every response carries
`Cache-Control: no-store`. Answers larger than 256 KiB, or slower than 2 s, are treated
by the area as "module not reachable". Paths are relative to the module's service.

### 3.1 Read all groups — `GET {base_path}`

```json
{
  "contract": 1,
  "module": "flow",
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
      "runtime": {"options": {"folder": [{"value": "f-12", "title": {"de": "Einkauf"}}]}}
    }
  }
}
```

- `contract` is the generation of the module API (1); the area serves a window like the
  registry's `api`. A module outside the window is shown read-only.
- A settings group carries `etag`, `values` (every declared key, the module's default
  where the person chose nothing) and optionally `runtime`. A collection group carries
  `etag`, `count` and optionally `runtime`; its items are read separately (3.3).
- A group the person may not use is left out. A module that answers `403` on this
  request is not shown at all; the area derives no rights itself.

**Runtime may only narrow** what the declaration allows; the area drops any runtime
entry that would widen it and never offers it:

| `runtime` entry | Shape | Rule |
|---|---|---|
| `options.<key>` | list of `{value, title?}` | for declared options: a subset of the declared values (the declared titles are used); for `options: runtime`: 0..64 entries with valid values and titles (≤ 80) — the only source of the options |
| `bounds.<key>` (integer) | `{"min": n, "max": m}` | within the declared `min`..`max` |
| `bounds.<key>` (text) | `{"max_length": n}` | at most the declared `max_length` |
| `bounds.<key>` (date) | `{"max_days": n}` | at most the declared `max_days` |

### 3.2 Replace one group — `PUT {base_path}/{group}`

Request (header `If-Match: "n-3"`):

```json
{"values": {"channels": ["chat"], "mute_info": false, "quiet_hours": true,
            "digest": "off", "locale": "de"}}
```

The body holds the whole group, every declared key; the module replaces the group as a
whole. Answer `200`:

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
                 "folder": "f-12", "until": "2026-12-31"},
      "operations": ["end", "renew"]
    }
  ]
}
```

- `id` matches `^[A-Za-z0-9_-]{1,64}$`; `state` is `active`, `ended` or `expired`;
  `operations` lists the declared operations this item allows now (never `create`).
- `POST {base_path}/{group}/items` with `{"fields": {...}}` creates an item when
  `create` is declared: `201` with the item and a `Location` header. An optional
  `Idempotency-Key` header makes a repeated request answer with the first item.
- `POST {base_path}/{group}/items/{id}/{operation}` with header `If-Match: <item etag>`
  and an optional body `{"fields": {...}}` (for example a new `until` for `renew`):
  `200` with the item.

### 3.4 Errors

Every error body is `{"code": "<code>", ...}`. The area translates codes from its own
catalogue; a `message` from the module (plain text, ≤ 300 characters) is shown only as
text and never interpreted.

| Status | `code` | Meaning |
|---|---|---|
| `400` | `malformed_request` | not JSON, or not the shape above |
| `401` | `unauthorized` | token missing, invalid or not for this audience |
| `403` | `forbidden` | the person may not use this group or item |
| `403` | `step_up_required` | sensitive group: a fresh sign-in is needed; `max_age` (s) names how fresh |
| `404` | `unknown_group`, `unknown_item`, `unknown_operation` | |
| `409` | `not_allowed_now` | the operation does not fit the item's state |
| `412` | `stale` | the ETag in `If-Match` is not the current one; `etag` names the current one |
| `428` | `precondition_required` | `If-Match` is missing |
| `422` | `invalid` | values do not pass the module's checks; `errors` lists them |

```json
{"code": "invalid",
 "errors": [{"pointer": "/values/digest", "code": "not_an_option"},
            {"pointer": "/values/channels/1", "code": "duplicate"}]}
```

`pointer` is a JSON Pointer (RFC 6901) into the request body. Codes of an entry:

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

`GET {data.summary}` → `200`, categories with counts, never content:

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

`GET {data.export}` → `200`, the person's own data, machine-readable, built on every call
and never stored:

```json
{"contract": 1, "module": "flow", "subject": "<sub>",
 "generated_at": "2026-11-20T09:00:00Z", "data": {"...": "module specific"}}
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
  installs there without personal settings. An add-on needs `requires.addon_api: 4` only
  when it attaches `me-web` (`networks.attach: [me-web]`) so the area can reach its API.
