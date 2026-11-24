# Netz

Dieses Kapitel nennt jede Verbindung, die eine Installation annimmt oder aufbaut, und alles,
was das Netz des Betreibers verlässt. Die einzige Quelle ist die Datei
[`security/comm-matrix.yaml`](../../../security/comm-matrix.yaml) des Kerns; die Tabelle unten
gibt sie auf Deutsch wieder, ein Test hält beide gleich. Die englische Erklärung der Felder
steht in [Network routes](../../network.md).

## Kommunikationsmatrix

Richtung: „eingehend“ zum Rand, „intern“ zwischen den Docker-Netzen, „ausgehend“ aus einem
Container nach außen, „Host“ vom Docker-Host selbst. Weg: „Ausgang“ über den einzigen Ausgang
`papaia-egress` ([The single exit](../../egress.md)), „direkt“ ohne ihn, „–“ bleibt im Host.
„Pflicht“ heißt: nötig, sobald die Bedingung in „Wann“ gilt.

| Nr | Richtung | Von | Netz der Quelle | Nach | Port/Protokoll | Zweck | Wann | Pflicht | Weg |
|---|---|---|---|---|---|---|---|---|---|
| K-01 | eingehend | Browser (Betreibernetz) | Betreibernetz | Rand (`nginx-proxy-manager`) | 443, 80/tcp | alle Oberflächen und die Anmeldung; 80 leitet nur auf 443 um | immer | Pflicht | – |
| K-02 | intern | Rand | `papaia-net` | `keycloak` | 8443/tcp | Anmeldung (TLS) | immer | Pflicht | – |
| K-03 | intern | Rand | `papaia-net` | `librechat`, `papaia-manager` und die Oberflächen der Module | 3080, 8000/tcp | Oberflächen und APIs; die Ports eines Moduls stehen in seinem Manifest | je Modul | Pflicht | – |
| K-04 | intern | Module, `librechat`, `papaia-manager` | `papaia-net` oder Netz des Moduls | `keycloak` | 8443/tcp | Discovery, JWKS, Token-Tausch (RFC 8693) | immer | Pflicht | – |
| K-05 | intern | Module, `librechat` | `papaia-net` oder Netz des Moduls | `litellm` | 4000/tcp | Modellaufrufe über das Modell-Gateway | immer | Pflicht | – |
| K-06 | intern | `litellm` | `papaia-net` | `localai` (Container oder natives LocalAI auf `host.docker.internal`) | 8080/tcp | lokales Modell | Profil `localai` | wahlweise | – |
| K-07 | intern | Module | Netz des Moduls | Module | –/tcp | Verkehr zwischen Modulen, wie ihre Manifeste sie koppeln (HTTP, TLS, MCP) | je Kopplung | wahlweise | – |
| K-08 | intern | `mcp-paperless` | internes Netz des Moduls Paperless | `paperless` | –/tcp | Vertrauenskopf von Paperless, nie am Rand | Modul Paperless | wahlweise | – |
| K-09 | intern | `papaia-manager` | `papaia-docker-gate-net` | `papaia-docker-gate` (Docker-Socket; der Vermittler lässt nur die Aufrufe seines Filters durch) | –/tcp | Status, Sicherungsplan, Start und Stopp benannter Projekte | Profil `manager` | wahlweise | – |
| K-10 | ausgehend | `smtp-relay` | `papaia-net` | Mailserver des Betreibers | 587, 465/tcp | einziger Mail-Ausgang (STARTTLS oder TLS) | Profil `smtp` | wahlweise | Ausgang |
| K-11 | ausgehend | `papaia-audit` | `papaia-egress-net` | SIEM | 6514, 443/tcp | Audit-Export (Syslog über TLS nach RFC 5425 oder JSON-Zeilen über HTTPS) | sobald ein SIEM-Ziel eingetragen ist | Pflicht | Ausgang |
| K-12 | ausgehend | Sicherung (`papaia-ctl` auf dem Host) | Host | Sicherungsziel | –/file | Archive und Löschjournal (Dateisystem, NFS oder SMB) | immer | Pflicht | direkt |
| K-13 | Host | Docker-Host | Host | NTP-Server | 123/udp | Zeit | immer | Pflicht | – |
| K-14 | ausgehend | `mcp-mssql` | `papaia-sql-uplink` | SQL Server des Betreibers (geschützter Host mit Katalogeintrag `mssql`) | 1433/tcp | Lesezugriff der SQL-Quelle; einziger direkter Weg zu einem Produktivsystem, durch Host-Regeln auf die geschützten Hosts und ihre Ports begrenzt | geschützter Host mit Katalogeintrag `mssql.<name>` | wahlweise | direkt |
| K-15 | ausgehend | `papaia-audit` | Host | Sicherungsziel | –/file | Kettenköpfe (`audit-heads`) außerhalb des Hosts | immer | Pflicht | direkt |
| K-16 | ausgehend | `keycloak` | `papaia-egress-net` | vorgelagerter Anmeldedienst | 443/tcp | Token-, JWKS- und Discovery-Endpunkte | Föderation | wahlweise | Ausgang |
| K-17 | ausgehend | `papaia-lifecycle` | `papaia-egress-net` | Verzeichnis-API des vorgelagerten Anmeldedienstes | 443/tcp | Statusabgleich alle 60 Sekunden | Föderation | wahlweise | Ausgang |
| K-18 | ausgehend | `papaia-egress` | `papaia-egress-net` | Unternehmensproxy | –/tcp | einziger Ausgang der Dienste; der Port kommt aus `PAPAIA_EGRESS_UPSTREAM_PROXY` | `PAPAIA_EGRESS_UPSTREAM_PROXY` ist gesetzt | wahlweise | Ausgang |
| K-19 | Host | Docker-Daemon des Hosts | Host | Image-Registry oder Spiegel des Betreibers | 443/tcp | Images laden bei Installation und Upgrade | Installation und Upgrade | Pflicht | – |
| K-20 | ausgehend | `litellm` | `litellm-egress` | Modellserver außerhalb der Installation | 443/tcp | Modellaufrufe an einen Modellserver, den papAIa nicht betreibt; die Inhalte der Anfragen verlassen das Netz; der Port kommt aus `api_base` des Modells | Modellroute außerhalb des Stapels | wahlweise | Ausgang |
| K-21 | intern | `papaia-audit` | `papaia-audit-idp-net` | `keycloak` | 8443/tcp | Berechtigungsbericht: Lesen des Realms als `svc-papaia-audit-report` (nur GET); das Netz teilen nur Keycloak und `papaia-audit`, ohne Weg nach außen | immer (Profil `audit`, mitgelieferter Keycloak) | Pflicht | – |

Die Zeilen mit den Zielen dieser Installation (Adressen, Ports des Proxys, Mailserver,
SIEM) gibt `papaia-ctl topology firewall` aus, als Tabelle, JSON oder CSV
(`--format=table|json|csv`). Diese Ausgabe ist die Vorlage für die Freigaben in der Firewall
und für die Liste der DNS-Namen vor der Installation (`papaia-ctl hostnames`).
`papaia-ctl doctor network` prüft den direkten Weg K-14 und seine Host-Regeln,
`papaia-ctl doctor egress` den einzigen Ausgang.

### Noch nicht umgesetzt

Bei diesen Zeilen gilt der Weg der Tabelle in dieser Version noch nicht:

- K-09: Der Manager bindet den Docker-Socket weiterhin auch selbst ein; der Weg allein über
  den Vermittler `papaia-docker-gate` ([The Docker socket broker](../../docker-gate.md)) gilt
  noch nicht. Zugriff auf den Docker-Socket entspricht Root-Rechten auf dem Host: Wer den
  Container `papaia-manager` steuert, steuert den Host. Ein nur lesend eingebundener Socket
  begrenzt die Docker-API nicht; begrenzt wird sie allein durch den Filter von
  `papaia-docker-gate`.
- K-10: SMTP lässt sich nicht durch `papaia-egress` leiten (nur CONNECT); das Mail-Relais
  sendet direkt.
- K-11: Der Export an ein SIEM ist nicht Teil dieser Version.
- K-16: Die Föderation läuft in dieser Version nicht über `papaia-egress`.
- K-17: Der Statusabgleich mit dem Verzeichnis ist nicht Teil dieser Version.

## Ausgangsliste

Alles, was das Netz des Betreibers verlässt. Zeilen ohne Matrixzeile laufen nicht über einen
Container mit eigenem Weg, sondern über den Host oder über `papaia-net`.

| Ziel | Matrixzeile | Wann | Abschaltbar |
|---|---|---|---|
| Image-Registry (`ghcr.io`, `docker.io`, `quay.io`) oder Spiegel des Betreibers | K-19 | Installation, Upgrade | ja, über einen eigenen Spiegel (Frage 13 von `setup`, `registry`) |
| `github.com` (Kern-Repo und Release-Tags) | keine; `git` auf dem Host | Installation, `papaia-ctl upgrade` | ja, über einen eigenen Spiegel des Repos |
| NTP-Server | K-13 | immer | nein |
| Sicherungsziel | K-12, K-15 | immer | nein |
| Mailserver des Betreibers | K-10 | Profil `smtp` | ja, Installation ohne Mail (`mail: none`) |
| SIEM | K-11 | sobald ein Ziel eingetragen ist | ja, ohne Ziel |
| SQL Server des Betreibers | K-14 | Data mit SQL-Quelle | ja, ohne SQL-Quelle |
| Vorgelagerter Anmeldedienst | K-16, K-17 | Föderation | ja, ohne Föderation |
| Unternehmensproxy | K-18 | `PAPAIA_EGRESS_UPSTREAM_PROXY` ist gesetzt | ja |
| Modellserver außerhalb der Installation | K-20 | Profil `small-no-model` oder `large`, oder eine eigene Modellroute | nein, nur durch Wechsel auf `small` mit lokalem Modell |
| Modellquellen (`huggingface.co`) | keine; Einrichtungscontainer `localai-model-init` und `speaches-model-init` | erster Start mit lokalem Modell oder Sprache | ja, Volumes `localai-models` bzw. `speaches-hf-cache` vorbefüllen |
| Websuche (Ziele von SearXNG und Firecrawl) | keine; Profil `librechat-websearch` | nur mit Websuche | ja, Profil aus |
| Let's Encrypt (ACME) | keine; der Rand | nur, wenn im Rand ein Let's-Encrypt-Zertifikat angelegt ist | ja, Zertifikat `internal` oder eigenes Bündel (Frage 3 von `setup`) |

Prüfen lässt sich die Liste mit einem Mitschnitt am Ausgang des Hosts (zum Beispiel
`tcpdump` auf der Schnittstelle nach außen) über einen Arbeitstag: Jede Verbindung muss zu
einer Zeile dieser Liste gehören.
