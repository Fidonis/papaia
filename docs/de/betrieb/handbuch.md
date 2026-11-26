# Betriebshandbuch

Dieses Handbuch richtet sich an die Personen, die papAIa auf einem eigenen Server betreiben:
installieren, Module wählen, das Netz freigeben, Störungen beheben, sichern und Anfragen
betroffener Personen bearbeiten. Es fasst die Betriebsteile auf Deutsch zusammen; die
vollständige Befehlsreferenz steht englisch in der [README](../../../README.md).

Alle Befehle laufen auf dem Host im Verzeichnis des Kern-Repos als `tools/papaia-ctl …`. Im
Handbuch steht kurz `papaia-ctl …`.

## Kapitel

| Kapitel | Inhalt |
|---|---|
| [Größe und Profile](groesse.md) | Größenprofile, Vorgabemodell, Anteil je Kern-Profil und Modul, Messen der Belegung |
| [Netz](netz.md) | Kommunikationsmatrix (eingehend, zwischen den Docker-Netzen, ausgehend), Ausgangsliste, Freigaben für die Firewall |
| [Module](module.md) | Abhängigkeitsmatrix Modul × Modul, Module nachrüsten und entfernen |
| [Neustart und Dauerlauf](neustart-und-dauerlauf.md) | Verhalten bei Neustart des Hosts, von Docker und einzelner Container; was im Dauerbetrieb wächst |
| [Störungsleitfaden](stoerungen.md) | Abschnitte S-1 bis S-10 und Diagnose, auf die `papaia-ctl doctor` verweist |
| [Sicherung](sicherung.md) | Sicherung durch den Hypervisor, Kopien außer Haus |
| [Wiederherstellung](../wiederherstellung.md) | Wiederherstellung aus einer Sicherung, nach Verlust des Hosts, zurückgesetzter Server, Rückweg nach einem Upgrade |
| [Auskunft und Löschung](auskunft-und-loeschung.md) | Betroffenenanfrage in sechs Schritten, auch ohne aktives Konto |
| [Anmeldung und Einstieg](anmeldung-und-einstieg.md) | Einstiegsseite, gemeinsame Anmeldeseite, Abmeldung |
| [Nachweis mit dem ausgelieferten Modell](modellnachweis.md) | Prüfung der Module mit dem kleinsten ausgelieferten Modell |
| [Lizenz und Bezug](lizenz-und-bezug.md) | Lizenz, Kosten und Bezug je Bestandteil |
| [Datenschutzunterlagen](../datenschutz/index.md) | Verzeichnis der Verarbeitungstätigkeiten, Protokollierung, TOM, Eckpunkte einer Betriebsvereinbarung |

## Installation

Die Installation eines Servers braucht sieben Befehle für den Kern und je Modul einen
weiteren (Einzelheiten: README, Abschnitt „Fresh installation“):

1. Kern-Repo in der freigegebenen Version holen (`git clone --branch v<Version> …`).
2. `papaia-ctl hostnames` nennt die DNS-Namen, die vor der Installation angelegt werden.
3. `papaia-ctl doctor` prüft den Host gegen das kleinste Größenprofil (Prüfpunkt
   `profile_size`, siehe [Größe und Profile](groesse.md)). Liegt der Host darunter, bricht
   `setup` vor jeder Änderung ab und nennt die fehlende Größe.
4. `papaia-ctl setup` fragt höchstens fünfzehn Eingaben ab (Domain, Zertifikat, Anmeldedienst,
   erste Verwaltungsperson, Module, Größenprofil, Modellquelle, Mail, Sicherungsziel,
   Sicherungsschlüssel, Registry, Kopplungen). Statt am Terminal zu antworten, liest
   `setup --answers=<Datei>` eine Antwortdatei.
5. `papaia-ctl addon install <modul> --path=<verzeichnis>` je gewähltem Modul.
6. `papaia-ctl start` startet Kern und alle installierten Module.
7. `papaia-ctl doctor` endet mit Ausgang 0.
8. `papaia-ctl backup` legt den ersten Wiederherstellungspunkt an.

Vorher: Docker installieren, die DNS-Einträge anlegen, das Sicherungsziel einhängen und die
Freigaben aus der [Kommunikationsmatrix](netz.md) in der Firewall eintragen.

## Upgrade und Rückweg

`papaia-ctl upgrade` hebt den Kern auf eine neue Version; jedes Upgrade legt vorher einen
Wiederherstellungspunkt und einen einmaligen Rückwegschlüssel an. Der Rückweg ist
`papaia-ctl rollback` (siehe [Wiederherstellung](../wiederherstellung.md#rückweg-nach-einem-upgrade)).
Ein Modul hebt `papaia-ctl addon upgrade <modul> --path=<verzeichnis>`.

## Vorabversionen testen (Test-Vertrauensanker)

Nur für Testinstallationen einer Vorabversion, nie im Produktivbetrieb. Ein Kern, dessen
`VERSION` eine Vorabversion ist (zum Beispiel `1.10.0-rc.1`), lässt sich gegen eine Stückliste
mit Geltungsbereich `test` prüfen, die mit einem lokalen Testschlüssel signiert ist. Dafür nehmen
`papaia-ctl setup`, `start`, `upgrade`, `pairing list`, `pairing confirm` und `suite verify` die
Option `--test-trust-anchor=<öffentlicher Schlüssel>` an:

- Bei `setup` wirkt sie nur auf die beiden Schritte, die die Stückliste lesen: die Anzeige und
  Bestätigung der Paarungen und das anschließende Modulangebot. Alle anderen Schritte bleiben
  unverändert. Ohne die Option endet `setup` auf einer Vorabversion mit Test-Stückliste wie
  bisher mit Rückgabewert 3.

- Sie gilt nur für diesen einen Befehl. Keine Umgebungsvariable, kein Eintrag in der `.env` und
  kein gespeicherter Zustand schaltet sie ein.
- Ein Kern mit Release-Version lehnt sie ab, bevor er irgendetwas anderes liest. Bei einem
  Upgrade müssen installierter Kern und Ziel Vorabversionen sein.
- Angenommen wird nur eine Stückliste mit Geltungsbereich `test`, signiert mit genau diesem
  Schlüssel. Eine Lieferstückliste (`delivery`) braucht weiter den festgeschriebenen
  Release-Schlüssel `compat/release-key.pub`; mit der Option wird sie abgelehnt.
- Am Anfang und am Ende des Befehls steht ein Warnhinweis mit dem Fingerabdruck des Schlüssels
  und „NOT FOR PRODUCTION“. Jede Prüfung mit dem Testschlüssel schreibt eine Zeile in das
  Audit-Log `$PAPAIA_CONFIG_DIR/audit/papaia-ctl.jsonl` (Befehl, Fingerabdruck, Prüfsumme der
  Stückliste, ausführende Person, Korrelationskennung).

Beispiele:

```bash
papaia-ctl setup -y --app-host=https://papaia.example.org --test-trust-anchor=/pfad/zum/testschluessel.pub
papaia-ctl start --test-trust-anchor=/pfad/zum/testschluessel.pub
```

Der nächste Befehl ohne Option prüft wieder streng gegen den Release-Schlüssel.

## Begriffe

Das Handbuch schreibt die Begriffe wie die Oberflächen: „Upgrade“, „Löschjournal“,
„Audit-Log“, „Assistant“, „Mein Bereich“ (kurz „Me“).
