# papAIa-Plattform — Architektur-Konzept

| Feld         | Wert                                         |
|--------------|----------------------------------------------|
| **Version**  | 1.0.0                                        |
| **Datum**    | 2026-06-25                                   |
| **Status**   | Draft — aktiv                                |
| **Scope**    | Plattform-Architektur, Extension-Kontrakt,   |
|              | Workspace-Topologie, Deployment-Modell       |
| **Author(en)**   | Marko Böhm     |

---

## 1. Kontext & Problemstellung

Fidonis führt mit dem **papAIa-Stack** KI bei mittelständischen Unternehmen ein.
Das zentrale Versprechen ist **Datenhoheit** — alle Daten bleiben beim Kunden.

### Ausgangslage (IST)

Der Stack ist heute ein **monolithischer Compose-Verbund**: anwendungsspezifische
Dienste (Paperless + MCP-Paperless, Qdrant-RAG + Ingest, n8n, SearXNG, Firecrawl)
werden per `include:` in `papaia/src/docker-compose.yml` gezogen. Ihre
Integrationspunkte sind **hart in den Core-Configs verdrahtet**:

- `librechat.yaml` → `mcpServers` / `allowedDomains`
- `homepage/config/services.yaml` → Service-Karten
- Keycloak-Realm-Clients + Audience-Mapper

Jede zusätzliche Anwendung vergrößert den Core und koppelt ihn an Dienste, die
nicht jeder Kunde braucht. Das skaliert weder über viele Kunden noch ist es
wartbar.

### Zielbild (SOLL)

Ein **Lean Core** (nur generische Plattform-Dienste) mit **leeren,
app-agnostischen Aufnahmepunkten** wird über einen einheitlichen
**Extension-Kontrakt** um anwendungsspezifische Module erweiterbar — jede
Extension in einem eigenen Repo, jederzeit hinzufüg- oder entfernbar, ohne den
Core zu verändern.

---

## 2. Ziel-Architektur — Überblick

### 3-Tier-Modell + 4 querliegende Prinzipien

```
                   ┌─────────────── PAPAIA-PLATTFORM (pro Kunde, ein Host) ───────────────┐
                   │                                                                        │
  Tier 1: CORE     │  Identity (Keycloak + oauth2-proxy)  Ingress (Nginx Proxy Manager)   │
  (immer,          │  AI-Runtime (LibreChat + LiteLLM [+ LocalAI])  Dashboard (Homepage)  │
  self-sufficient) │                                                                        │
                   │  Integrations-Registry = LEERE, app-agnostische Aufnahmepunkte:       │
                   │    mcpServers-Slot · Homepage-Slot · Realm (Basis-Clients) · NPM-Host │
                   │                           ▲     ▲     ▲                                │
                   │               (5 Nähte: Netz · OIDC · MCP · Homepage · Ingress)       │
                   └───────────────────────────┼─────┼─────┼────────────────────────────┘
                                               │     │     │   einheitlicher Extension-Kontrakt
               ┌───────────────────────────────┘     │     └───────────────────────────────┐
               │                                      │                                      │
  Tier 2: KURATIERTER FIDONIS-EXTENSION-KATALOG       │   Tier 3: KUNDEN-APPLIKATIONEN      │
  (Fidonis-gepflegt, zubuchbar, je eigenes Repo)      │   (bespoke pro Kunde, je eigenes    │
                                                       │    Repo, gleicher Kontrakt)         │
  • RAG-Bundle (qdrant-rbac + Qdrant + Jina)          │   • Muster A: bestehende App        │
  • Dokumente (Paperless + paperless-mcp-rbac)         │     mit MCP-Server umhüllen         │
  • Automation (n8n)                                   │   • Muster B: Kundendaten in        │
  • Suche (SearXNG)                                    │     RAG ingestieren (role-scoped)   │
  • Web-Crawling (Firecrawl)                           │   • Muster C: Hybrid                │
               │                                       │                                      │
               └──────── jede Extension: eigenes Netz, nur MCP-Seam zur AI-Runtime ─────────┘

  Querliegend:
  ① DATENHOHEIT        — local-first Inferenz, per-User-RBAC am Datenrand, Netz-Isolation
  ② GEMISCHTES HOSTING — self-hosted + Fidonis-managed, gleiches Laufzeit-Artefakt
  ③ FLOTTEN-SKALIERUNG — SemVer-Compat, image-basiert, idempotente Update-Runs
  ④ REPO-INTEGRITÄT    — Repos bleiben read-only (git pull), alles Generierte im Config-Ordner
```

---

## 3. Tier 1 — Core: Plattform, nicht App-Sammlung

Im Core bleibt **nur**, was jede Instanz als generische Plattform braucht:

| Dienst-Gruppe | Komponenten |
|---------------|-------------|
| Identity      | Keycloak (OIDC-Provider), oauth2-proxy (Header-Injektion) |
| Ingress       | Nginx Proxy Manager (NPM) |
| AI-Runtime    | LibreChat (Chat-UI), LiteLLM (LLM-Gateway), LocalAI (opt-in local inference) |
| Dashboard     | Homepage |

Die Integrations-Punkte des Core werden zu **leeren, app-agnostischen
Aufnahmepunkten** entkernt — kein hart verdrahteter App-Bezug mehr. Der Core
ist **self-sufficient**: er startet und läuft vollständig ohne jede Extension.

### Core-Aufnahmepunkte

```
librechat.yaml     →  mcpServers: []        (leer, von Extensionen befüllt)
                       allowedDomains: []    (leer, von Extensionen befüllt)
services.yaml      →  nur Core-Dienste      (Extensionen fügen Service-Karten hinzu)
Keycloak-Realm     →  Basis-Clients         (Extension-Clients additiv registriert)
NPM                →  Core-Hosts            (Extension-Hosts additiv angelegt)
```

---

## 4. Tier 2 — Kuratierter Fidonis-Extension-Katalog

Fidonis-eigene Optional-Module — je **eigenes Repo**, als **versionierte Images**
konsumiert. Sie nutzen **denselben** Extension-Kontrakt wie Kunden-Apps (eine
Mechanik), sind aber Fidonis-gepflegt, qualitätsgesichert und als Katalog
„zubuchbar".

Unterschied zu Tier 3 = **Eigentümerschaft / Trust / Katalog-Listing**, nicht
der Mechanismus.

---

## 5. Tier 3 — Kunden-Applikationen

Bespoke pro Kunde, je eigenes Repo, gleicher Kontrakt. Drei wiederkehrende Muster:

| Muster | Beschreibung | Beispiel |
|--------|--------------|---------|
| **A** — MCP-Wrap | Bestehende App mit OIDC/RBAC-MCP-Server umhüllen | CRM-System + `mcp-crm-rbac` |
| **B** — RAG-Ingest | Kundendaten in das RAG-Bundle ingestieren, role-scoped Retrieval | Produktdatenbank → Qdrant |
| **C** — Hybrid | MCP-Wrap + RAG-Ingest kombiniert | ERP mit MCP + Wissens-RAG |

„Neue Kunden-App einbinden" = Repo nach Schablone anlegen + Eintrag in `deployment.yaml`.

---

## 6. Der Extension-Kontrakt

### 6.1 Dateistruktur einer Extension

```
extensions/papaia-ext-<name>/
├── papaia-app.yaml          # Manifest: deklarativer Kontrakt (alle Metadaten)
├── docker-compose.yml       # App + zugehöriger MCP-Server, auf EIGENEM Netz
├── .env.example             # App-Secrets-Template (wird in $PAPAIA_CONFIG_DIR/.env geseedet)
├── integration/             # Die 5 Nähte als Fragmente (alle optional)
│   ├── keycloak/            # OIDC-Clients + Audience-Mapper JSONs
│   ├── librechat/           # mcpServers + allowedDomains Fragment (YAML)
│   ├── homepage/            # Dashboard-Service-Eintrag (YAML)
│   └── nginx/               # Optionaler Ingress-Snippet
└── README.md                # Self-contained manueller Integrationspfad (public-clean)
```

> **Kein `papaia-app.sh` pro Extension.** Alle Lifecycle-Verben (`install`,
> `update`, `remove`) werden zentral von `papaia-ctl` ausgeführt — kein
> Delegations-Skript pro Extension nötig.

### 6.2 `papaia-app.yaml` — Manifest-Schema

```yaml
name: <kurzname>                    # Eindeutiger Bezeichner (a-z, 0-9, -)
version: <semver>                   # Extension-Version
extension_repo: papaia-ext-<name>   # GitHub-Repo-Name
papaia_compat: ">=<semver>"         # Minimale Core-Version
description: "<Beschreibung>"

networks:
  app_network: papaia-<name>-net    # Eigenes Bridge-Netz der Extension
  attach: [nginx, librechat]        # Core-Container, die ans App-Netz angehängt werden

integration:
  keycloak:
    clients: [integration/keycloak/<client>.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/<name>.yaml   # optional
  homepage:  integration/homepage/<name>.yaml    # optional
  nginx:     integration/nginx/<name>.conf        # optional
```

### 6.3 Beispiel A: `papaia-ext-paperless`

```yaml
name: paperless
version: 1.0.0
extension_repo: papaia-ext-paperless
papaia_compat: ">=0.8.0"
description: "Paperless-ngx document management + OIDC/RBAC MCP server"
networks:
  app_network: papaia-paperless-net
  attach: [nginx, librechat]
integration:
  keycloak:
    clients: [integration/keycloak/paperless.json, integration/keycloak/mcp-paperless.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/paperless.yaml
  homepage:  integration/homepage/paperless.yaml
  nginx:     integration/nginx/paperless.conf
```

**Datenhoheit:** `mcp-paperless` validiert Keycloak-Bearer + Audience und leitet
Requests als `X-Papaia-Remote-User` weiter — Paperless erzwingt seine eigene
per-User-RBAC. Kein Admin-Credential im MCP-Layer.

### 6.4 Beispiel B: `papaia-ext-qdrant-rbac`

```yaml
name: qdrant-rbac
version: 0.1.0
extension_repo: papaia-ext-qdrant-rbac
papaia_compat: ">=0.8.0"
description: "Qdrant vector DB + OIDC/RBAC MCP server for RAG workloads"
networks:
  app_network: papaia-qdrant-net
  attach: [librechat]
integration:
  keycloak:
    clients: [integration/keycloak/qdrant-rbac.json]
    client_mappers:
      librechat: [integration/keycloak/librechat-audience-mapper.json]
  librechat: integration/librechat/qdrant-rbac.yaml
  homepage:  integration/homepage/qdrant-rbac.yaml
```

**Datenhoheit:** `mcp-qdrant-rbac` validiert Bearer + Audience und scopt
Qdrant-Queries auf die Collections, auf die der User Zugriff hat (JWT je
Collection-ACL).

---

## 7. Die 5 Nähte (Extension-Integration-Punkte)

Alle 5 Nähte sind **standardisiert**, nicht handverdrahtet. Welche Nähte eine
Extension nutzt, ist im Manifest optional deklariert.

### Naht 1 — Netz: „Core attacht an App"

Die Extension definiert ihr eigenes Bridge-Netz. Der Orchestrator generiert
automatisch eine **Override-Compose** (`$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml`),
die das App-Netz als `external: true` referenziert und die im Manifest unter
`attach:` gelisteten Core-Container (z. B. `nginx`, `librechat`) an das App-Netz
hängt. Der Core-Compose bleibt unverändert.

```yaml
# Beispiel: generierter Override für paperless
services:
  librechat:
    networks:
      - papaia-paperless-net
  nginx-proxy-manager:
    networks:
      - papaia-paperless-net
networks:
  papaia-paperless-net:
    external: true
```

### Naht 2 — OIDC

Client-JSONs aus `integration/keycloak/` werden **additiv und idempotent** in
den Keycloak-Realm registriert (via Keycloak Admin REST API oder Bootstrap-Skript),
inkl. Audience-Mapper für den MCP-Token-Flow. Basis: bestehender idempotenter
Keycloak-Client-Sync in `papaia/src/infra/keycloak/bootstrap.sh`.

### Naht 3 — LibreChat-MCP

Das `mcpServers`- und `allowedDomains`-Fragment aus `integration/librechat/`
wird **beim Render** in die effektive `librechat.yaml` im Config-Ordner gemerged.
Der Render-Prozess: Base-Template + Σ aktive Extension-Fragmente + Kunden-Overlay.

### Naht 4 — Homepage

Der Service-Eintrag aus `integration/homepage/` wird beim Render in
`services.yaml` im Config-Ordner gemerged. Die Homepage mountet ausschließlich
die gerenderte Datei aus `$PAPAIA_CONFIG_DIR/services/homepage/config/`.

### Naht 5 — Ingress (optional)

Optionaler NPM-Proxy-Host-Eintrag für die Extension-UI. Wird über den
Nginx-Fragment-Mechanismus (oder NPM API) additiv angelegt.

---

## 8. Inversion of Control — Orchestrator `papaia-ctl`

Der Orchestrator lebt in `papaia/tools/papaia-ctl` und ist damit Teil des
öffentlichen Core-Repos (Community-nutzbar). Er liest das **Deployment-Manifest**
(`$PAPAIA_CONFIG_DIR/deployment.yaml`) und ruft pro Extension den entsprechenden
`docker compose`-Befehl in der richtigen Reihenfolge auf.

**Neue Extension = Repo klonen + Eintrag in `deployment.yaml` + `papaia-ctl apps integrate <name>`.**
Kein Core-Eingriff.

### Verfügbare Verben

| Kommando | Was passiert |
|---|---|
| `papaia-ctl init` | Config-Ordner anlegen, `.env` + `deployment.yaml` seeden |
| `papaia-ctl apps integrate <name>` | .env seeden → aktiv setzen → Configs rendern → Override generieren |
| `papaia-ctl apps deintegrate <name>` | Override entfernen → Configs neu rendern → inaktiv setzen |
| `papaia-ctl apps install <name>` | `docker compose -f extensions/…/docker-compose.yml up -d` |
| `papaia-ctl apps update <name>` | `docker compose … pull && up -d` + `render` |
| `papaia-ctl apps remove <name>` | `deintegrate` + `docker compose … down` |
| `papaia-ctl apps render` | 3-Schicht-Merge für alle aktiven Extensions → Config-Ordner |
| `papaia-ctl up [profile...]` | Render + alle aktiven Apps starten + Core-Compose up |
| `papaia-ctl down [profile...] [--volumes]` | Core down + alle aktiven Apps stoppen |

### `.env`-Seeding bei `integrate`

`integrate` liest `.env.example` der Extension und fügt **fehlende Keys
non-destruktiv** in `$PAPAIA_CONFIG_DIR/.env` ein (sticky reuse — bestehende
Werte bleiben). Secret-Keys (Muster `SECRET|PASSWORD|KEY|TOKEN`) mit Platzhalter
erhalten automatisch einen zufälligen Wert (`secrets.token_urlsafe`), sodass
Realm-Client-Secret und App denselben Wert teilen (eine Quelle).

---

## 9. Workspace-Topologie

### Verzeichnisstruktur

```
[workspace-root]/
│
├── extensions/                          # Tier-2- und Tier-3-Extensions (je eigenes GitHub-Repo)
│   ├── papaia-ext-paperless/
│   │   ├── papaia-app.yaml
│   │   ├── docker-compose.yml
│   │   ├── .env.example
│   │   └── integration/
│   │       ├── keycloak/
│   │       ├── librechat/
│   │       ├── homepage/
│   │       └── nginx/
│   │
│   └── papaia-ext-qdrant-rbac/
│       ├── papaia-app.yaml
│       ├── docker-compose.yml
│       ├── .env.example
│       └── integration/
│           ├── keycloak/
│           ├── librechat/
│           └── homepage/
│
├── papaia/                              # Tier 1 — Core-Repo (Fidonis/papaia, public-bound)
│   ├── docs/                            # Architekturdokumentation, ADRs, Extension-Spec
│   ├── src/                             # Core-Implementierung
│   │   ├── docker-compose.yml           # Lean Core (mountet ausschließlich aus $PAPAIA_CONFIG_DIR)
│   │   ├── .env.example                 # Core-Env-Template
│   │   ├── ai/                          # Base-Templates (librechat.yaml.base, litellm.yaml.base)
│   │   ├── infra/                       # Keycloak-Realm-Base, Bootstrap-Skripte
│   │   ├── services/                    # Homepage-Base-Config
│   │   └── catalog.yaml                 # Bekannte Extensions (Name, Repo-URL, Tags, Tier)
│   └── tools/                           # Orchestrator
│       ├── papaia-ctl                   # init · up/down · apps list|render|integrate|…
│       ├── deployment.template.yaml     # Template für deployment.yaml im Config-Ordner
│       └── lib/
│           ├── render_core.py           # 3-Schicht-Merge → Config-Ordner
│           └── gen_override.py          # Seam-1-Override generieren → Config-Ordner
│
└── papaia-config/                       # Config-Ordner (pro Kunde/Env, KEIN Repo, gitignored)
    ├── deployment.yaml                  # SSOT: aktive Extensions + Versionen + Core-Profile
    ├── .env                             # Secrets + Env-Vars (gitignored, geseedet bei init)
    ├── ai/librechat/librechat.yaml      # GENERIERT (Base + Extensions + Overlay)
    ├── ai/litellm/config.yaml           # GENERIERT
    ├── infra/keycloak/realm-import/     # GENERIERT (Secrets eingebacken, immer render-owned)
    ├── services/homepage/config/        # GENERIERT
    ├── overrides/                       # GENERIERTE docker-compose.<ext>.override.yml
    └── overlay/                         # Kunden-Overlay (hand-authored, überlebt Re-Render)
        ├── ai/librechat/librechat.yaml
        └── services/homepage/config/services.yaml
```

### Repo-Mapping

| Workspace-Pfad | GitHub-Repo | Sichtbarkeit |
|---|---|---|
| `papaia/` | `Fidonis/papaia` | public-bound |
| `papaia/tools/` | Teil von `Fidonis/papaia` | public-bound |
| `extensions/papaia-ext-paperless/` | `Fidonis/papaia-ext-paperless` | public-bound |
| `extensions/papaia-ext-qdrant-rbac/` | `Fidonis/qdrant-rbac` | public-bound |
| `papaia-config/` | — (kein Repo) | gitignored, pro Kunde/Env |

---

## 10. Namenskonventionen

### Extension-Repos: `papaia-ext-<name>`

| Kontext | Namensschema | Beispiel |
|---|---|---|
| GitHub-Repo | `papaia-ext-<name>` | `papaia-ext-paperless` |
| Workspace-Verzeichnis | `extensions/papaia-ext-<name>/` | `extensions/papaia-ext-paperless/` |
| Manifest-Feld `name:` | `<name>` (Kurzname) | `paperless` |
| `deployment.yaml` → `path:` | `extensions/papaia-ext-<name>` | `extensions/papaia-ext-paperless` |
| Docker-Netz | `papaia-<name>-net` | `papaia-paperless-net` |

### Config-Ordner

Der Config-Ordner heißt **`papaia-config`**, konfigurierbar via Env-Var:

```bash
export PAPAIA_CONFIG_DIR=/srv/fidonis/papaia-prod/config   # absoluter Pfad in Produktion
# Default (ohne Export): <workspace-root>/papaia-config
```

### Interne Struktur

| Bereich | Pfad | Inhalt |
|---|---|---|
| Core-Implementierung | `papaia/src/` | Compose, Base-Templates, Bootstrap-Skripte |
| Orchestrator | `papaia/tools/` | `papaia-ctl`, Render-Bibliotheken |
| Extension | `extensions/papaia-ext-<name>/` | Manifest, Compose, Fragments |
| Config-Ordner | `papaia-config/` | Generierte Configs, Secrets, Overlay |

---

## 11. Querliegende Prinzipien

### ① Datenhoheit (Kernversprechen)

- **State auf Kunden-Infra**: alle Daten in Named Volumes auf dem Kunden-Host;
  auch im managed Betrieb single-tenant — Fidonis hält keine Kundendaten.
- **Local-first Inferenz**: LocalAI als Default-Backend über LiteLLM; externe
  LLM-APIs sind **opt-in** und an genau einer Stelle (LiteLLM) zentral
  abschaltbar → „nichts verlässt das Haus" ist erzwingbar und auditierbar
  (ein Egress-Punkt).
- **Autorisierung am Datenrand, nicht nur in der UI**: MCP-Server validieren
  Keycloak-Bearer + Audience und scopen **jeden** Request:
  - `mcp-qdrant-rbac` → Qdrant-JWT per Collection-ACL (role-scoped Retrieval)
  - `mcp-paperless` → `X-Papaia-Remote-User` → native Paperless-RBAC
- **Netz-Isolation**: jede Extension auf eigenem Bridge-Netz; nur der MCP-Seam
  ist zur AI-Runtime exponiert; Reverse-Proxy strippt Trust-Header aus externem
  Verkehr (Defense-in-Depth).

### ② Gemischtes Hosting (gleiches Laufzeit-Artefakt)

| Betriebsmodell | Wer agiert | Pfad |
|---|---|---|
| **Self-hosted** | Kunde oder geführte Installation | `papaia/README.md` (manuell) |
| **Fidonis-managed** | Fidonis betreibt single-tenant per Kunde | Private Tooling + zentrale Update-Verteilung |

Beide Modelle erzeugen dasselbe Laufzeit-Artefakt aus denselben Repos. Der
Unterschied liegt im Tooling-Pfad, nicht im Stack.

### ③ Flotten-Skalierung & Wartbarkeit

- **SemVer-Kompatibilitäts-Kontrakt**: Core veröffentlicht eine SemVer-Plattform-
  Version; jede Extension deklariert `papaia_compat: ">=x.y.z"`; der Orchestrator
  verweigert inkompatible Kombinationen. Das macht Flotten-Updates sicher.

  > **SemVer-Kurzreferenz:** `MAJOR.MINOR.PATCH` — MAJOR bricht die Abwärts-
  > kompatibilität (Extensions müssen explizit angepasst werden), MINOR fügt
  > Funktionen abwärtskompatibel hinzu, PATCH behebt Fehler ohne API-Änderung.
  > `papaia_compat: ">=0.8.0"` bedeutet: diese Extension läuft auf jeder
  > Core-Version ab 0.8.0 aufwärts, solange MAJOR 0 bleibt.

- **Image-basierte Distribution**: Extensions als gepinnte Images aus
  `ghcr.io/fidonis/...`, nicht als Source. Update = Ref bumpen + idempotentes
  `integrate` re-applizieren; Rollback = vorheriger Image-Pin.
- **Per-Kunde-Deployment-Manifest**: `deployment.yaml` im Config-Ordner ist
  die **Single Source of Truth** je Install (Core-Profile + aktive Extensions
  + Versionen + Hosting-Typ). Treibt Orchestrator und Update-Runs.
- **Idempotenz durchgängig**: `integrate`, `render`, `up` sind re-runnable
  ohne Seiteneffekte → unbeaufsichtigte Flotten-Updates möglich.
- **Lean Core = weniger Wartung**: entkoppelte Lebenszyklen — Core upgradet
  unabhängig von Extensions, Extensions unabhängig vom Core (innerhalb der
  Compat-Range).

### ④ Keine Repo-Änderungen am Kunden (Config-Ordner-Externalisierung)

Dies ist das **load-bearing Muster** für den Upgrade-Pfad beim Kunden:

- **Repos = read-only zur Deploy-Zeit**: Core-Repo, Extension-Repos, Tooling —
  keinerlei Mutation durch Integrate / Deploy / Update-Runs. `git pull` bleibt
  immer konfliktfrei.
- **`$PAPAIA_CONFIG_DIR` = alles Materialisierte**: gerenderte effektive Configs,
  generierte Overrides, generiertes `papaia-realm.json` (Secrets eingebacken),
  Deployment-Manifest, `.env`, Kunden-Overlay.
- **Core-Compose mountet ausschließlich aus `$PAPAIA_CONFIG_DIR/...`**.
- **Kein generiertes Artefakt liegt im Repo-Baum** (`.gitignore`-Disziplin).

---

## 12. Deployment-Manifest (`deployment.yaml`)

Das Manifest im Config-Ordner ist die **einzige** deklarative Quelle für den
Zustand einer Installation.

### Schema

```yaml
customer: <kundenname>              # Eindeutiger Bezeichner der Installation
platform_version: 0.8.0            # Aktive Core-Version
hosting: self-hosted | managed      # Betriebsmodell

core:
  profiles:                         # Aktive Docker-Compose-Profile
    - keycloak
    - oauth2-proxy
    - nginx
    - librechat
    - litellm
    - homepage
  inference: local-first | external # LLM-Inferenz-Modus

extensions:
  - name: paperless                 # Kurzname (= Manifest-Feld name:)
    path: extensions/papaia-ext-paperless  # Workspace-relativer Pfad zum Extension-Repo
    version: 1.0.0                  # Gepinnte Version
    active: true                    # false = installiert aber nicht integriert
  - name: qdrant-rbac
    path: extensions/papaia-ext-qdrant-rbac
    version: 0.1.0
    active: false                   # auskommentiert / inaktiv
```

### Aktiv-Set

Der Orchestrator leitet das Aktiv-Set (welche Extensions am Render und am
`docker compose up` teilnehmen) aus `active: true`-Einträgen ab. Das Manifest
selbst wird nie von `integrate`/`deintegrate` gelöscht — nur `active`-Flag
und `version` werden gesetzt.

---

## 13. Kunden-Overlay — 3. Render-Schicht

Der Config-Ordner enthält ein optionales `overlay/`-Verzeichnis für
kundenspezifische Anpassungen. Overlay-Dateien werden **nie von `papaia-ctl`
überschrieben** und überleben jeden Re-Render.

### 3-Schicht-Merge

```
Repo-Base  (papaia/src/*.base.*)
  + Σ aktive Extension-Fragmente  (extensions/papaia-ext-*/integration/*)
  + Kunden-Overlay  ($PAPAIA_CONFIG_DIR/overlay/*)
  ───render──▶  effektive Config in $PAPAIA_CONFIG_DIR/...
```

### Typische Overlay-Anwendungsfälle

**Zusätzlicher LLM-Endpoint** (`overlay/ai/librechat/librechat.yaml`):
```yaml
endpoints:
  custom:
    - name: "Kunden-LLM-Gateway"
      apiKey: "${CUSTOMER_LLM_API_KEY}"
      baseURL: "https://llm.kunde.internal/v1"
      models:
        default: ["gpt-4o"]
```

**Unternehmens-Links im Dashboard** (`overlay/services/homepage/config/services.yaml`):
```yaml
- Firma:
    - Intranet:
        href: "https://intranet.kunde.internal"
        description: Unternehmens-Intranet
        icon: mdi-home-city
```

---

## 14. papaia-manager — Web-basiertes Extension-Management

### Motivation

`papaia-ctl` ist ein CLI-Orchestrator — ideal für Administratoren, aber kein
zugänglicher Weg für Nicht-Techniker, Extensions anzusehen, auszuprobieren oder
zu installieren. Der **papaia-manager** bietet eine Web-UI auf Basis derselben
Orchestrator-Logik.

### Rolle: optionaler Core-Service (kein Extension)

Der Manager verwaltet Extensions — er darf nicht selbst eine Extension sein
(zirkuläre Abhängigkeit). Er ist ein **optionaler Core-Service** in
`papaia/src/docker-compose.yml` hinter einem Compose-Profile (`manager`).

### Stack

| Schicht | Wahl | Begründung |
|---|---|---|
| Backend | FastAPI (Python) | Direkte Imports von `render_core.py` + `gen_override.py` |
| Frontend | HTMX + Jinja2 | Kein Build-Step; bleibt im Python-Ecosystem |
| Docker API | `docker` Python SDK + subprocess | Typsicher + Fallback für `docker compose` |
| Katalog | `catalog.yaml` in `papaia/src/` | Versioniert, offline-fähig |
| Auth | oauth2-proxy (Naht 2, Rolle `admin`) | Vorhanden — kein eigenes OIDC nötig |
| Ingress | Nginx-Fragment (Naht 5) | Analog zu Extension-Ingress-Regeln |

### Dateistruktur

```
papaia/src/
├── catalog.yaml              # Bekannte Extensions: Name, Repo-URL, Beschreibung, Tags, Tier
└── manager/
    ├── Dockerfile
    ├── main.py               # FastAPI App
    ├── routers/
    │   └── extensions.py     # GET/POST /extensions/{name}/install|update|remove|activate
    ├── services/
    │   ├── catalog.py        # Liest catalog.yaml — "verfügbare" Extensions
    │   ├── deployment.py     # Liest/schreibt deployment.yaml — "installierte" Extensions
    │   └── orchestrator.py   # Ruft papaia-ctl via subprocess auf
    └── templates/
        ├── index.html        # Extension-Galerie (Katalog + Status)
        └── extension.html    # Detailansicht mit Action-Buttons
```

### Katalog-Format (`catalog.yaml`)

```yaml
extensions:
  - name: paperless
    repo: https://github.com/Fidonis/papaia-ext-paperless
    description: Dokumentenmanagement mit OCR und OIDC/RBAC MCP-Server
    category: productivity
    tier: 2
    tags: [documents, ocr]
  - name: qdrant-rbac
    repo: https://github.com/Fidonis/papaia-ext-qdrant-rbac
    description: Qdrant Vector-DB mit OIDC/RBAC für RAG-Workloads
    category: ai
    tier: 2
    tags: [rag, vector-db]
```

### Execution Model

Der Manager ruft `papaia-ctl` via subprocess auf — keine Re-Implementierung
der Logik:

```python
# orchestrator.py
def run_ctl(*args):
    return subprocess.run(
        ["bash", "/workspace/papaia/tools/papaia-ctl", *args],
        capture_output=True, text=True
    )

install = lambda name: run_ctl("apps", "install", name)
update  = lambda name: run_ctl("apps", "update",  name)
remove  = lambda name: run_ctl("apps", "remove",  name)
```

> **Sicherheitshinweis:** Der `name`-Parameter aus der URL muss gegen
> `[a-z0-9-]+` validiert werden, bevor er in Shell-Kommandos verwendet wird.

### Docker-Compose

```yaml
papaia-manager:
  build: ./manager
  profiles: [manager]
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock   # Docker API
    - ${WORKSPACE_ROOT}:/workspace                 # papaia-ctl + Extensions
    - ${PAPAIA_CONFIG_DIR}:/config                 # deployment.yaml lesen/schreiben
  networks:
    - papaia-net
```

### Integration in die 5 Nähte

| Naht | Manager-Integration |
|---|---|
| Naht 2 (OIDC) | Hinter `oauth2-proxy`; Keycloak-Rolle `admin` required |
| Naht 4 (Dashboard) | Eintrag in `services.base.yaml` → erscheint in Homepage |
| Naht 5 (Ingress) | `manager.${PAPAIA_HOST}` → Nginx-Forward an Container-Port |
| Naht 1, 3 | Keine direkte Nutzung |

### UI-Konzept: Extension-Karten

Jede Karte zeigt:
- Name + Beschreibung (aus `catalog.yaml` / `papaia-app.yaml`)
- Status-Badge: `available` · `installed` · `active`
- Version + Update-verfügbar-Hinweis
- Action-Button kontextuell: **Download & Install → Activate ↔ Deactivate → Remove**
- Seam-Indikatoren: welche Integrationspunkte die Extension nutzt

### Offene Designfrage

| Option | Beschreibung | Bewertung |
|---|---|---|
| **A — MVP** | Manager verwaltet nur lokal vorhandene Extensions in `extensions/` | Schneller zu implementieren |
| **B — Store** | Manager klont bei „Install" automatisch aus `catalog.yaml` (`git clone`) | Echter Marketplace-Feel; empfohlen für Folge-Iteration |

---

## 15. Roadmap

| Phase | Inhalt | Status |
|---|---|---|
| **Phase 0** — Spec & Blueprint | Architektur-Spec, Extension-Kontrakt-Schema, ADR definieren; Manifest-Schema validieren gegen existierende Beispiele | Abgeschlossen |
| **Phase 1** — Core entschlacken + Pilot Paperless | App-spezifische Includes + hartverdrahtete Configs aus Core lösen; `papaia-ext-paperless` als erstes Companion-Repo; `papaia-ctl`-Verben; End-to-End verifizieren | Prototype vorhanden (verifiziert) |
| **Phase 2** — Tooling härten | App-Registry + `papaia-ctl apps` vollständig; sourcebare Merge-Helfer (YAML-Merge, Keycloak-Register, Override-Netz-Generierung); Per-Kunde-Deployment-Manifest treibt Komposition | Offen |
| **Phase 3** — Katalog + Kunden-Apps + Flotte | Restliche First-Party-Module einzeln in Katalog migrieren (RAG-Bundle, n8n, Suche, Firecrawl); Companion-App-Template-Repo für Kunden (Muster A + B); Flotten-Update-Verteilung (Versions-Pinning, Compat-Gating, Rollback) | Offen |

---

## 16. Offene Punkte

| Punkt | Beschreibung | Empfehlung |
|---|---|---|
| Extension-Sichtbarkeit | Generische Tier-2-Extensions public-bound oder privat? | Public-bound (No-Trace-Pflicht beachten) |
| MCP-Erreichbarkeit | East-west (librechat ans App-Netz) vs. über Ingress | East-west als Default; im Manifest pro Extension wählbar |
| `PAPAIA_CONFIG_DIR`-Default | Sibling `<repo>-config` wie heute vs. `/srv/fidonis/<env>/config` | Sibling für Dev, absoluter Pfad für Prod |
| Compat-Policy-Strenge | Warn vs. Hard-Fail bei `papaia_compat`-Verletzung | Hard-Fail in Produktion; Warn in Dev-Modus |
| Pre-Release-Kanäle | `>=x.y.z-rc` oder separater Kanal für Beta-Extensions | Offen |
| `papaia/tools/` öffentlich | Orchestrator ist public-bound; Fidonis kann private Optimierungen schichten | Community-Orchestrator in `papaia/tools/`; privater Fast-Path bleibt getrennt |
| papaia-manager: Katalog-Download | Git-Clone bei „Install" (Option B) in Prototyp implementieren? | Empfehlung: Folge-Iteration nach Phase-2-Tooling |

---

## 17. Verifikations-Checkliste

### Architektur-Validierung

- [ ] **Kontrakt-Realitäts-Check**: Existierende Paperless- und Qdrant-Einträge lassen
  sich verlustfrei als `papaia-app.yaml` + Fragmente ausdrücken.
- [ ] **Mapping-Trockenlauf**: Hartverdrahtete Einträge (`librechat.yaml mcpServers`,
  `services.yaml`, Realm-Clients) → Ziel-Fragmente dokumentiert.

### Prototyp-Verifikation

| Check | Erwartetes Ergebnis |
|---|---|
| `papaia-ctl init` | `papaia-config/` anlegen, `.env` + `deployment.yaml` seeden |
| `papaia-ctl apps integrate paperless` | `papaia-config/` aktualisiert; Repos unverändert |
| Hash `papaia/` + `extensions/` vor/nach integrate | **Identisch** (Repo-Pristine-Beweis) |
| `papaia-ctl apps render` (2×) | Identische Outputs (Idempotenz) |
| Overlay greift | `papaia-config/overlay/ai/librechat/librechat.yaml` erscheint im rendered Output |
| `docker compose -f papaia/src/docker-compose.yml config` | Valide; nur Core-Services; kein Paperless |
| Seam-1-Override aktiv | `librechat` + `nginx` an `papaia-net` **und** `papaia-paperless-net` |
| `.env`-Seeding | `KC_PAPERLESS_CLIENT_SECRET` (zufällig) + App-Keys vorhanden; zweites `integrate` ändert nichts |
| `up keycloak` | Nur Keycloak + DB starten |
| `up` (voll) | Core-Profile + Paperless-App + Override aktiv |
| `down --volumes` | Alle Container + Volumes entfernt |

### Public-Clean-Audit (für Artefakte in public-bound Repos)

- [ ] Keine Referenz auf interne Tooling-Repos in `papaia/docs/` + ADRs
- [ ] Kein Verweis auf interne Skripte oder Installer
- [ ] Kein „AI" außer im Produktnamen papAIa; kein „agent" im Sinne von KI-Tools
- [ ] Alle Nähte rein technisch beschrieben (LibreChat `mcpServers`, OIDC-Client, NPM, Homepage)
