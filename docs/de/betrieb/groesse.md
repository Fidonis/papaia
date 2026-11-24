# Größe und Profile

Ein Größenprofil beschreibt die Hardware, auf der papAIa geprüft wird. Es schaltet keine
Funktion und keine Freigaberegel; das Vier-Augen-Prinzip ist eine eigene Einstellung
(`papaia-ctl settings`).

## Größenprofile

| Profil | Kerne | Arbeitsspeicher | freie Platte | Inhalt | Modell |
|---|---|---|---|---|---|
| `small-no-model` | 8 | 32 GB | 200 GB | „klein ohne Modell“: Kern, Manager, Me, Studio, Data, Flow, Assistant, Paperless | eigener Modellserver des Betreibers außerhalb des Hosts (Frage 8 von `setup`) |
| `small` | 8 | 64 GB, oder 32 GB und eine GPU mit 16 GB Grafikspeicher | 300 GB | „klein“: wie „klein ohne Modell“ und LocalAI mit dem Vorgabemodell | Vorgabemodell auf diesem Host (unten) |
| `large` | 16 | 64 GB | 500 GB, dazu ein Sicherungsziel mit mindestens dem Dreifachen des Datenbestands | „groß“: wie „klein ohne Modell“ | eigener Modellserver des Betreibers, zum Beispiel ein eigener GPU-Host |

- `setup` fragt das Profil (Frage 7) und speichert es als `PAPAIA_SIZE_PROFILE`.
- `papaia-ctl doctor profile_size` misst Kerne, Arbeitsspeicher und freie Platte: vor
  `setup` gegen das kleinste Profil, danach gegen das gewählte. Liegt ein Wert darunter,
  bricht `setup` vor jeder Änderung ab und nennt, was fehlt, zum Beispiel
  `CPU: 8 cores needed, 4 found`.
- Gemessen wird, was Docker sieht; unter Docker Desktop also die VM von Docker Desktop, nicht
  der Rechner. Beim Arbeitsspeicher gelten 5 % weniger als im Profil noch als ausreichend
  (Anteil des Betriebssystemkerns).
- Die Profile sind Mindestwerte für alle Module zusammen. Eine Auswahl von Modulen braucht
  nicht weniger Kerne oder Platte, aber weniger Container; den Anteil zeigen die Tabellen
  unten.

## Vorgabemodell

Mit dem Profil `small` richtet `setup` genau ein lokales Modell in LocalAI ein:

| Variante | Alias im Modell-Gateway | Modell | Quantisierung | Größe der Datei | Lizenz |
|---|---|---|---|---|---|
| CPU | `qwen2.5-7b-instruct-q4` | Qwen2.5-7B-Instruct (GGUF) | Q4_K_M | rund 4,7 GB | Apache-2.0 |
| GPU (NVIDIA, 16 GB) | `qwen2.5-7b-instruct-q8` | Qwen2.5-7B-Instruct (GGUF) | Q8_0 | rund 8 GB | Apache-2.0 |

Für die Prüfung der Module mit dem kleinsten ausgelieferten Modell dient
`qwen2.5-1.5b-instruct` (siehe [Nachweis mit dem ausgelieferten Modell](modellnachweis.md)).
Die GPU-Variante braucht einen NVIDIA-Treiber mit CUDA und das NVIDIA Container Toolkit auf
dem Host; in einer virtuellen Maschine muss die GPU durchgereicht werden. Das Modell wird
beim ersten Start heruntergeladen (siehe [Ausgangsliste](netz.md#ausgangsliste)).

## Anteil je Kern-Profil

Gezählt aus den Compose-Dateien des Kerns: Container sind die Dienste des Profils (einmalige
Einrichtungscontainer eingeschlossen), Images die verschiedenen Images, Volumes die benannten
Docker-Volumes, Ports die auf dem Host veröffentlichten Ports. Ein Dienst, der in mehreren
Profilen steht, zählt in jedem. Die Zeile „gesamt“ ist der Kern mit allen Profilen, jedes
Image und Volume einmal gezählt.

| Kern-Profil | Container | Images | Volumes | veröffentlichte Ports | Zweck |
|---|---|---|---|---|---|
| `audit` | 3 | 2 | 1 | 0 | Audit-Log `papaia-audit` mit Datenbank |
| `connections` | 3 | 2 | 2 | 0 | Verbindungsregister |
| `egress` | 1 | 1 | 0 | 0 | einziger Ausgang `papaia-egress` |
| `keycloak` | 2 | 2 | 1 | 0 | Anmeldedienst mit Datenbank |
| `knowledge-map` | 1 | 1 | 1 | 0 | KI-Landkarte |
| `librechat` | 5 | 5 | 6 | 0 | Chat mit Datenbanken |
| `librechat-websearch` | 8 | 8 | 2 | 0 | Websuche für den Chat |
| `lifecycle` | 4 | 3 | 2 | 0 | Entzug, Löschjournal des Anmeldedienstes, Startsperre, Nachspielen von Löschungen in Chat und Modell-Gateway (`papaia-replay`) |
| `litellm` | 3 | 3 | 2 | 0 | Modell-Gateway mit Datenbank und Messwerten |
| `localai` | 2 | 2 | 2 | 0 | lokales Modell (Profil `small`; nativ auf einem Mac ohne Container) |
| `manager` | 2 | 2 | 0 | 0 | Manager und `papaia-docker-gate` |
| `me` | 3 | 2 | 1 | 0 | Mein Bereich und Einstellungsdienst |
| `nginx` | 2 | 2 | 0 | 3 | Rand (443, 80; Verwaltungs-API nur auf 127.0.0.1) |
| `oauth2-proxy` | 1 | 1 | 0 | 0 | Anmeldung vor Diensten ohne eigene Anmeldung |
| `people` | 1 | 1 | 0 | 0 | Personensuche für Module |
| `rag` | 4 | 4 | 3 | 0 | Wissenssuche mit Qdrant |
| `smtp` | 1 | 1 | 1 | 0 | Mail-Relais |
| `voice` | 3 | 3 | 2 | 0 | Sprache (Erkennung und Ausgabe) |
| `gesamt` | 49 | 41 | 26 | 3 | alle Kern-Profile |

## Anteil je Modul

Gezählt aus der Compose-Datei des Moduls in der Version dieser Suite: die Dienste, die
`papaia-ctl addon start` startet. Dienste, die nur für einzelne Aktionen oder als wahlweise
Teile laufen (eigenes Compose-Profil), sind nicht mitgezählt. Kein Modul veröffentlicht einen
Port; erreichbar sind Module nur über den Rand.

| Modul | Container | Images | Volumes | veröffentlichte Ports | Hinweis |
|---|---|---|---|---|---|
| Studio | 9 | 7 | 6 | 0 | Apps, Baukasten, eigene Datenbank |
| Data | 3 | 2 | 4 | 0 | Dashboards, eigene Datenbank |
| Flow | 15 | 4 | 10 | 0 | Abläufe, Arbeiter, eigene Datenbank |
| Assistant | 10 | 2 | 6 | 0 | Assistent, eigene Datenbank |
| Paperless | 7 | 7 | 4 | 0 | Dokumentenablage mit MCP-Server |

Für eine Auswahl von Modulen addieren sich die Zeilen: Kern-Profile der Installation plus die
gewählten Module. `papaia-ctl status` zeigt dieselben Container je Modul mit ihrem Zustand;
`papaia-ctl addon components <modul>` nennt die Bestandteile eines Moduls mit ihren Versionen.

## Messen

Die Profile sind die Größen, gegen die `doctor` prüft. Die Belegung einer laufenden
Installation misst der Betrieb selbst, am besten nach einem vollständigen Arbeitstag:

```sh
docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}'
docker system df
papaia-ctl status
papaia-ctl metrics --out=/tmp/papaia-messwerte.prom
```

- Der Spitzenwert des Arbeitsspeichers soll höchstens 85 % der Ausstattung erreichen; darüber
  ist das nächstgrößere Profil zu wählen oder ein Modul abzuschalten.
- Kein Container darf wegen Speichermangel beendet worden sein (`docker inspect` zeigt dann
  `OOMKilled: true`).
- `papaia-ctl doctor docker_usage` und `papaia-ctl doctor disk_space` warnen, bevor Platte oder
  Docker-Speicher knapp werden.

Für diese Version liegen keine eigenen Messwerte der Belegung je Profil vor; die Tabellen oben
geben Zahl und Art der Container an, nicht ihren Speicherbedarf.
