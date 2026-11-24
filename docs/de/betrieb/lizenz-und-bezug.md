# Lizenz und Bezug

Dieses Dokument sagt dem Betreiber je Bestandteil der Lieferung, unter welcher Lizenz er steht, ob er
ohne Gebühr genutzt werden darf und ob dafür ein Vertrag nötig ist; dazu, woher die Images kommen, wie
lange sie abrufbar bleiben, wie der Ausstieg geht und welche Pflichten beim Betreiber bleiben. Es ist
Teil der Lieferunterlagen (Anforderung OPS-13, Kriterien EXK-PLT-71-A1 bis A4 und EXI-PLT-69-A1 bis
A3).

Stand: Kern 1.10.0. Die Images und Versionen des Kerns stehen in
[`THIRD_PARTY_LICENSES.md`](../../../THIRD_PARTY_LICENSES.md); bei Abweichung gilt die signierte
Stückliste der Version.

**Keine Rechtsberatung.** Das Dokument nennt Lizenzen und die daraus folgenden technischen und
organisatorischen Regeln. Die rechtliche Bewertung für die eigene Installation trifft der Betreiber.

## 1 Lizenz je Bestandteil

### 1.1 Eigene Bestandteile

Spalten: Lizenz (SPDX), ob die Nutzung ohne Gebühr erlaubt ist, ob ein Vertrag mit Fidonis für die
Nutzung nötig ist, Hinweis zum Bezug.

| Bestandteil | Lizenz | Kostenfrei nutzbar | Vertrag nötig | Bezug und Hinweis |
|---|---|---|---|---|
| Kern | MIT | ja | nein | öffentliches Repo `Fidonis/papaia`, Images unter `ghcr.io/fidonis/` |
| Manager | MIT | ja | nein | öffentliches Repo `Fidonis/papaia-manager`, Image `ghcr.io/fidonis/papaia-manager` |
| Studio | MIT | ja | nein | Images über die Zugangsdaten der Lieferung (Abschnitt 3); `LICENSE` und `THIRD_PARTY_LICENSES.md` liegen im Image unter `/usr/share/doc/papaia-studio/` |
| Data | MIT | ja | nein | Images über die Zugangsdaten der Lieferung (Abschnitt 3) |
| Flow | MIT | ja | nein | als Modul der Suite; Images über die Zugangsdaten der Lieferung (Abschnitt 3) |
| Flow als eigenständige Edition | Alle Rechte vorbehalten (Fidonis GmbH), keine offene Lizenz erteilt | nein | ja | Nutzung der Edition außerhalb der Suite nur mit Vertrag; die Edition enthält nur Fremdbestandteile der Klassen „freizügig“ und „schwaches Copyleft“ |
| Assistant | MIT | ja | nein | Images über die Zugangsdaten der Lieferung (Abschnitt 3) |
| Mein Bereich | MIT | ja | nein | Image `ghcr.io/fidonis/papaia-me` (persönlicher Bereich `me-web` und Einstellungsspeicher `prefs`, Profil `me`) über die Zugangsdaten der Lieferung (Abschnitt 3) |
| Kit | MIT | ja | nein | Bibliothek der Module; Version 0.1.0 liegt im Kern als Paket unter `tools/vendor/papaia-kit/<version>/` (nur Entwicklungswerkzeug, nicht Teil von `papaia-ctl` oder eines Images); `LICENSE` liegt im Paket |
| Verbindungsregister | MIT | ja | nein | Images über die Zugangsdaten der Lieferung (Abschnitt 3) |
| KI-Landkarte | MIT | ja | nein | Image `ghcr.io/fidonis/papaia-knowledge-map` |
| Add-on-Sammlung | MIT | ja | nein | öffentliches Repo `Fidonis/papaia-addons`; die Fremdprodukte der Add-ons stehen in Abschnitt 1.2, n8n in Abschnitt 2 |
| MCP-Server Qdrant | MIT | ja | nein | öffentliches Repo `Fidonis/qdrant-mcp-rbac`, Image `ghcr.io/fidonis/qdrant-mcp-rbac` |
| MCP-Server Paperless | MIT | ja | nein | öffentliches Repo `Fidonis/paperless-mcp-rbac` |
| MCP-Server MediaWiki | MIT | ja | nein | Image über die Zugangsdaten der Lieferung (Abschnitt 3) |
| MCP-Server SQL Server | MIT | ja | nein | das Image enthält keinen Treiber von Microsoft; die Treiberschicht baut der Betreiber (Abschnitt 2) |

Eigene Images des Kerns (MIT, Hinweisdateien im Image unter `/usr/share/licenses/<image>/`):

| Image | Lizenz | Inhalt |
|---|---|---|
| `ghcr.io/fidonis/papaia-egress` | MIT | einziger Ausgang des Stapels; Basis `python` (PSF-2.0) |
| `ghcr.io/fidonis/papaia-lifecycle` | MIT | Kontolebenszyklus; Basis `python` (PSF-2.0) |
| `ghcr.io/fidonis/papaia-replay` | MIT | Löschungen in Chat und Modell-Gateway für die Kern-Startsperre; Basis `python` (PSF-2.0) |
| `ghcr.io/fidonis/papaia-audit` | MIT | Audit-Speicher; enthält psycopg (LGPL-3.0-only, unverändert) |
| `ghcr.io/fidonis/papaia-people` | MIT | Personensuche für die Assistenz |
| `ghcr.io/fidonis/papaia-docker-gate` | MIT | Vermittler zum Docker-Socket für den Manager |
| `ghcr.io/fidonis/jina-reranker-api` | Apache-2.0 | Umsortierung der Suchtreffer; Modell nach Abschnitt 1.3 |
| `ghcr.io/fidonis/qdrant-ingest` | MIT | geplante Übernahme von Dokumenten in Qdrant |

### 1.2 Mitgelieferte Fremddienste

Die Fremddienste laufen als getrennte, unveränderte Dienste; der Kern verweist nur auf ihre Images.
Kostenfrei heißt: die Lizenz erlaubt den Betrieb ohne Gebühr. Die Pflichten je Lizenzklasse stehen in
Abschnitt 8.

| Fremddienst | Lizenz | Kostenfrei nutzbar | Vertrag nötig | Auflage |
|---|---|---|---|---|
| Keycloak (`quay.io/keycloak/keycloak`) | Apache-2.0 | ja | nein | keine |
| PostgreSQL (`postgres`) | PostgreSQL | ja | nein | keine |
| pgvector (`pgvector/pgvector`) | PostgreSQL | ja | nein | keine |
| Python (`python`) | PSF-2.0 | ja | nein | Basis der eigenen Images; Debian-Pakete mit Quellangebot (Abschnitt 6) |
| Nginx Proxy Manager (`jc21/nginx-proxy-manager`) | MIT | ja | nein | keine |
| oauth2-proxy (`quay.io/oauth2-proxy/oauth2-proxy`) | MIT | ja | nein | keine |
| Postfix-Relay (`boky/postfix`) | MIT; enthält Postfix (IPL-1.0 oder EPL-2.0), OpenDKIM und rsyslog (GPL-3.0-or-later) | ja | nein | unverändert betreiben |
| HAProxy (`haproxy`) | GPL-2.0, Header LGPL-2.1 | ja | nein | unverändert betreiben; nur bei verteilter Installation |
| LibreChat (`ghcr.io/librechat-ai/librechat`) | MIT | ja | nein | keine |
| RAG-API von LibreChat (`ghcr.io/librechat-ai/librechat-rag-api-dev-lite`) | MIT | ja | nein | keine |
| MongoDB (`mongo`) | SSPL-1.0 | ja | nein | nur als interne Datenbank von LibreChat, unverändert, kein Angebot als Dienst an Dritte |
| Meilisearch (`getmeili/meilisearch`) | MIT; Enterprise-Teile BUSL-1.1 | ja | nein | nur die Community-Funktionen; Sharding bleibt aus |
| LiteLLM (`ghcr.io/berriai/litellm`) | MIT außerhalb `enterprise/` | ja | nein | keine Enterprise-Funktion einschalten |
| Prometheus (`prom/prometheus`) | Apache-2.0 | ja | nein | keine |
| LocalAI (`localai/localai`) | MIT | ja | nein | Modelle nach Abschnitt 1.3 |
| curl (`curlimages/curl`) | curl (MIT-artig) | ja | nein | keine |
| Qdrant (`qdrant/qdrant`) | Apache-2.0 | ja | nein | keine |
| Apache Tika (`docker.io/apache/tika`) | Apache-2.0 | ja | nein | keine |
| speaches (`ghcr.io/speaches-ai/speaches`) | MIT; enthält espeak-ng (GPL-3.0) und ffmpeg (GPL) | ja | nein | unverändert betreiben; nur mit dem Profil `voice` |
| Chatterbox TTS Server (`ghcr.io/devnen/chatterbox-tts-server`) | MIT | ja | nein | nur mit dem Profil `voice` |
| Firecrawl (`ghcr.io/firecrawl/firecrawl`) | AGPL-3.0 | ja | nein | unverändert betreiben; Quellangebot (Abschnitt 6) |
| Firecrawl MCP Server (`ghcr.io/firecrawl/firecrawl-mcp-server`) | AGPL-3.0 laut Bestandsliste des Kerns | ja | nein | unverändert betreiben; die strengere Angabe gilt, bis die Bestandsliste an der Quelle geprüft ist |
| Playwright-Dienst von Firecrawl (`ghcr.io/firecrawl/playwright-service`) | Apache-2.0 | ja | nein | keine |
| nuq-postgres von Firecrawl (`ghcr.io/firecrawl/nuq-postgres`) | PostgreSQL | ja | nein | keine |
| Redis (`redis`) | AGPL-3.0 gewählt (angeboten: RSALv2, SSPLv1, AGPLv3) | ja | nein | unverändert betreiben; nur für Firecrawl |
| RabbitMQ (`rabbitmq`) | MPL-2.0 | ja | nein | unverändert betreiben; nur für Firecrawl |
| SearXNG (`searxng/searxng`) | AGPL-3.0 | ja | nein | unverändert betreiben; Quellangebot (Abschnitt 6) |
| Caddy (Studio) | Apache-2.0 | ja | nein | keine |
| Valkey (Studio, Add-ons) | BSD-3-Clause | ja | nein | keine |
| socat (`alpine/socat`, Studio, Flow) | GPL-2.0 | ja | nein | getrennter Prozess, unverändert; nicht in der eigenständigen Flow-Edition |
| Paperless-ngx (Add-on) | GPL-3.0 | ja | nein | unverändert; Anbindung nur über die HTTP-Schnittstelle |
| Gotenberg (Add-on) | MIT | ja | nein | keine |
| MediaWiki mit Erweiterungen (Add-on, Image `ghcr.io/fidonis/papaia-mediawiki`) | GPL-2.0-or-later | ja | nein | Fidonis verbreitet das Image und trägt das Quellangebot (Abschnitt 6) |
| MariaDB (Add-on) | GPL-2.0 | ja | nein | unverändert betreiben |
| MediaWiki MCP Server (Add-on) | MIT | ja | nein | keine |

### 1.3 Modelle

| Modell | Lizenz | Kostenfrei nutzbar | Vertrag nötig | Rolle |
|---|---|---|---|---|
| `qwen2.5-7b-instruct-q4` (Qwen2.5-7B-Instruct, Q4_K_M) | Apache-2.0 | ja | nein | Vorgabemodell ohne Beschleuniger ([Modell-Gateway](../../model-gateway.md#default-model)) |
| `qwen2.5-7b-instruct-q8` (Qwen2.5-7B-Instruct, Q8_0) | Apache-2.0 | ja | nein | Vorgabemodell mit Beschleuniger |
| `qwen2.5-1.5b-instruct` (Qwen2.5-1.5B-Instruct, Q4_K_M) | Apache-2.0 | ja | nein | kleinste ausgelieferte Variante ([Modellnachweis](modellnachweis.md)) |
| `nomic-embed-text` (nomic-embed-text v1.5) | Apache-2.0 | ja | nein | Einbettungen für die Suche |
| `mistral-7b-instruct-v0.3` | Apache-2.0 | ja | nein | wählbar, nicht voreingestellt |
| faster-whisper-large-v3-turbo (Sprache, Profil `voice`) | MIT | ja | nein | Spracherkennung |
| Chatterbox (Sprache, Profil `voice`) | MIT | ja | nein | Sprachausgabe |

Das Modell hinter `jina-reranker-api` wählt der Betreiber mit `RERANKER_MODEL`. Modelle der Reihe
`jina-reranker-v1-*` stehen unter Apache-2.0; `jina-reranker-v2-base-multilingual` steht unter
CC-BY-NC-4.0 und ist nicht für den gewerblichen Einsatz freigegeben (Abschnitt 2).

## 2 Vom Betreiber selbst zu beschaffen

Diese Lizenzen beschafft und verantwortet der Betreiber selbst; Fidonis liefert sie nicht mit:

- **SQL Server**, wenn eine eigene Datenbank als Quelle angebunden wird: Lizenz von Microsoft für
  Ausgabe und Version. Die Developer-Ausgabe hat kein Recht zum Produktivbetrieb. SQL Server ist nie
  Teil der Lieferung, der Stückliste oder des Offline-Archivs.
- **Microsoft ODBC Driver 18 for SQL Server**: Der Betreiber baut die Treiberschicht des MCP-Servers
  SQL Server selbst aus der Paketquelle von Microsoft und nimmt dabei die Lizenz von Microsoft an
  (<https://aka.ms/odbc18eula>). Fidonis veröffentlicht kein Image mit Treiber.
- **n8n**: nicht Teil der Lieferung. Die Sustainable Use License erlaubt die Nutzung nur für eigene
  interne Geschäftszwecke (<https://github.com/n8n-io/n8n/blob/master/LICENSE.md>). Wer das Add-on
  installiert, prüft die Lizenz selbst und trägt die Verantwortung dafür.
- **Modelle mit eigener Lizenz**: `llama-3.1-8b-instruct` (Llama 3.1 Community License mit
  Nutzungsrichtlinie und der Namensnennung „Built with Llama“, <https://www.llama.com/llama3_1/license/>)
  ist wählbar, aber nicht voreingestellt; wer es einschaltet, nimmt diese Lizenz an. Dasselbe gilt für
  `jina-reranker-v2-base-multilingual` (CC-BY-NC-4.0) und jedes selbst eingetragene Modell.

## 3 Bezug der Images

**Weg.** Alle Images sind mit Tag und Digest festgeschrieben und mit dem Release-Schlüssel signiert;
`papaia-ctl start` und `upgrade` prüfen Digest und Signatur vor dem Start
([Image-Prüfung](../../../README.md#image-pinning-and-signatures)).

1. Images des Kerns und der öffentlichen Repos (`ghcr.io/fidonis/`, `quay.io`, `docker.io`) sind ohne
   Zugangsdaten abrufbar. Docker Hub begrenzt anonyme Abrufe; bei Bedarf meldet sich der Betreiber mit
   einem eigenen Konto an.
2. Images der Module aus nicht öffentlichen Repos liegen in der Registry von Fidonis. Mit der Lieferung
   erhält der Betreiber Zugangsdaten, die nur lesen dürfen. Er meldet den Host einmal an
   (`docker login <Registry der Lieferung>`) und führt dann `papaia-ctl start` aus. Genau diese
   Zugangsdaten und dieser Weg reichen für den Abruf aller Images der Stückliste (EXK-PLT-71-A2).
3. Mit einem eigenen Spiegel trägt der Betreiber `PAPAIA_IMAGE_MIRROR` in die `.env` ein; die Digests
   bleiben gleich.

**Abrufbarkeit.** Die Images jeder veröffentlichten Version bleiben unter ihrem Tag und Digest
mindestens 3 Jahre nach der letzten Auslieferung dieser Version abrufbar. Ein Tag wird nie auf ein
anderes Image umgesetzt. Die Frist entspricht der Frist des Quellangebots (Abschnitt 6).

**Offline-Archiv.** Das Offline-Archiv enthält alle Images der Lieferung (EXI-PLT-69-A2). n8n gehört
nicht zur Lieferung und ist deshalb nicht im Archiv; der Betreiber bezieht es selbst
(`docker.io/n8nio/n8n`). Bezug ist das Image, das das Add-on festschreibt:
`docker.io/n8nio/n8n:2.36.6`. Das Add-on schreibt nur den Tag fest; den Digest hält der Betreiber beim
Abruf fest (`docker image inspect --format '{{index .RepoDigests 0}}'`). Eine andere Version wählt er
über `N8N_IMAGE` auf eigene Verantwortung. Die Installation aus dem Archiv mit
einem Spiegel des Betreibers ist der Prüffall von EXI-PLT-69-A2.

**Ausstieg.** `papaia-ctl export --exit --out=<pfad>` exportiert je Modul den Bestand in einem offenen,
dokumentierten Format (EXI-PLT-69-A1): Apps und Versionen aus Studio, Definitionen aus Data, Abläufe
und Verbindungen ohne Geheimnisse aus Flow, Anlassregeln aus dem Assistant, Realm ohne Geheimnisse und
Plattformkatalog aus dem Kern. Persönliche Inhalte sind ausgenommen; für sie gilt der Export je
Person. Der Befehl gehört zur Suite und ist in dieser Kernversion noch nicht enthalten. Bis dahin
sichert `papaia-ctl backup` alle Volumes verschlüsselt an das Sicherungsziel des Betreibers
([Sicherung](../../../README.md#backup)); die Daten liegen dort in den Formaten der jeweiligen
Datenbank.

## 4 Keine Lizenzprüfung beim Start

Kein Dienst der Lieferung fragt beim Start oder im Betrieb eine Lizenz beim Hersteller ab, und keiner
braucht einen Lizenzschlüssel. Ein Host ohne ausgehende Verbindung und mit einer Uhr, die ein Jahr
vorgeht, startet den Stapel genauso (EXK-PLT-71-A3; Prüfung: Rauchprobe mit gesperrtem Ausgang und
vorgestellter Uhr). Der Ablauf von Zertifikaten ist davon getrennt und wird von `papaia-ctl doctor`
gemeldet.

## 5 Unterstützung und Sicherheitskorrekturen

- **Versionen.** Die aktuelle und die vorige Nebenversion erhalten Sicherheitskorrekturen. Das Ende
  einer Linie wird mindestens 6 Monate vorher angekündigt (EXK-PLT-71-A4).
- **Fristen.** Für eine kritische Schwachstelle erscheint ein Korrekturrelease spätestens 14 Tage,
  für eine hohe spätestens 30 Tage nach Bekanntwerden. Ein Hinweis an die Betreiber folgt innerhalb
  von 72 Stunden über das Banner im Manager und die Release-Notiz.
- **Prüfung.** Die eigenen Images des Kerns werden beim Build bei jeder Änderung (Pull-Request und
  Push) auf Schwachstellen geprüft und zusätzlich täglich: Der tägliche Lauf baut den Stand des
  Standardzweigs und prüft ihn erneut gegen die aktuellen Schwachstellendatenbanken
  (`.github/workflows/images.yml`). Die Fremd-Images, die der Kern unverändert bezieht, und die
  Images der Module, die der Kern pinnt (etwa Mein Bereich), werden wöchentlich und bei jeder
  Änderung unter `src/` geprüft (`.github/workflows/image-scan.yml`).
- **Meldeweg.** Schwachstellen bitte nie als öffentliches Issue melden, sondern über
  <https://github.com/Fidonis/papaia/security/advisories/new> oder an `security@fidonis.de`. Die
  Eingangsbestätigung folgt innerhalb von 3 Arbeitstagen ([Sicherheitsrichtlinie](../../../SECURITY.md)).
- Schwachstellen in Fremddiensten meldet der Betreiber dem jeweiligen Projekt; Fidonis liefert die
  korrigierte Version des Fremddienstes mit dem nächsten Release.

## 6 Schriftliches Quellangebot

Für die Bestandteile unter GPL, LGPL und AGPL in Images, die Fidonis selbst verbreitet (eigene Images
mit ihren Debian-Paketen, das MediaWiki-Image, gespiegelte Fremdimages im Offline-Archiv), stellt
Fidonis auf Anfrage den vollständigen Quelltext der ausgelieferten Fassung bereit: für jeden Empfänger
der Lieferung, für drei Jahre nach der letzten Auslieferung des Releases, gegen höchstens die Kosten
des Datenträgers. Anfrage an `security@fidonis.de` mit Version und Image. Für unverändert betriebene
Fremddienste, die der Host selbst beim Hersteller abruft, gilt das Angebot des jeweiligen Projekts.

## 7 Wegfall des Herstellers

Wie der Quelltext der nicht öffentlichen Repos bei Wegfall des Herstellers hinterlegt oder
veröffentlicht wird, regelt der Liefervertrag (EXI-PLT-69-A3). Alle Bestandteile außer der
eigenständigen Flow-Edition stehen schon heute unter einer offenen Lizenz (Abschnitt 1.1).

## 8 Pflichten des Betreibers

Die Liste ist keine Rechtsberatung, sondern die Regel je Lizenzklasse:

| Klasse / Bestandteil | Satz für den Betreiber |
|---|---|
| freizügig (MIT, Apache-2.0, BSD, PostgreSQL, PSF) | Keine Pflicht bei Betrieb; bei eigener Weitergabe die Lizenztexte mitgeben (sie liegen im Image). |
| schwaches Copyleft (MPL-2.0, LGPL, EPL-2.0) | Keine Pflicht bei unverändertem Betrieb; Änderung an der Komponente nur nach Rücksprache. |
| GPL, AGPL als Fremddienst | Keine Pflicht bei unverändertem Betrieb; die Pflichten als Verbreiter trägt Fidonis (Abschnitt 6). Wer verändert oder selbst weitergibt, übernimmt die Pflichten selbst; Änderung nur nach Rücksprache. |
| quelloffen, nicht frei (MongoDB, Meilisearch-Enterprise, LiteLLM `enterprise/`) | Nur unverändert und nur mit den freigegebenen Funktionen betreiben; kein Angebot als Dienst an Dritte. |
| n8n | Nur nach eigener Prüfung der Herstellerlizenz und auf eigene Lizenzverantwortung installieren. |
| Treiberschicht SQL Server | Der Betreiber baut sie selbst und nimmt dabei die Lizenz von Microsoft an. |
| SQL Server als eigene Quelle | Eigene Lizenz des Betreibers; die Developer-Ausgabe hat kein Produktivrecht. |
| Modelle | Lizenz des gewählten Modells beachten; die Vorgabemodelle stehen unter Apache-2.0, Modelle mit eigener Lizenz nur mit deren Richtlinie (Abschnitt 2). |
