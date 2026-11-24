# Störungsleitfaden

`papaia-ctl doctor` nennt bei jedem Fehler die Ursache in einem deutschen Satz und den
Abschnitt dieses Leitfadens, zum Beispiel „(siehe Handbuch §S-1)“. Jeder Abschnitt hat fünf
Teile: Anzeichen, Prüfung, Behebung, Rückkehr in den Normalzustand, Eskalation. Was keiner
der Abschnitte erklärt, behandelt [Diagnose](#diagnose).

Für alle Abschnitte gilt die Eskalation unten: Hilft die Behebung nicht, erstellt der Betrieb
mit `papaia-ctl support-bundle` ein Archiv (ohne Geheimnisse und ohne Inhalte) und gibt es an
den Dienstleister. Sicherheitslücken gehen nie in ein öffentliches Ticket, sondern an
<https://github.com/Fidonis/papaia/security/advisories/new>.

## S-1 Modell-Gateway läuft nicht

**Anzeichen.** Chat und die Funktionen der Module, die ein Modell brauchen, antworten mit
einer Fehlermeldung.

**Prüfung.** `papaia-ctl doctor container_health model_gateway` meldet `fail` mit dem Satz
„Das Modell-Gateway (LiteLLM) läuft nicht; Module können keine Modelle nutzen.“

**Behebung.**

```sh
papaia-ctl logs litellm --since=30m
papaia-ctl start --profiles=litellm
```

Startet `litellm` nicht, weil seine Datenbank `litellm-db` fehlt, zuerst
[S-4](#s-4-datenbank-eines-moduls-läuft-nicht), bei voller Platte
[S-7](#s-7-kein-platz-auf-der-datenplatte).

**Rückkehr.** `papaia-ctl doctor model_gateway` meldet `pass`; die Module nutzen das Modell ohne
Neustart wieder.

**Eskalation.** Bleibt der Container ungesund, Archiv aus `papaia-ctl support-bundle` an den
Dienstleister.

## S-2 Modell nicht geladen

**Anzeichen.** Anfragen an ein Modell scheitern, obwohl das Modell-Gateway läuft.

**Prüfung.** `papaia-ctl doctor model_ready` meldet „Das Modell <name> ist nicht geladen;
Anfragen schlagen fehl.“ Bei LocalAI auf einem Mac ohne Container prüft
`papaia-ctl doctor localai_native` den Prozess.

**Behebung.**

```sh
papaia-ctl logs localai --since=30m
papaia-ctl start --profiles=localai
```

Der Start lädt fehlende Modelldateien erneut (Einrichtungscontainer `localai-model-init`);
ohne Zugang zu den Modellquellen (siehe [Ausgangsliste](netz.md#ausgangsliste)) das Volume
`localai-models` vorbefüllen. Reicht der Arbeitsspeicher nicht, siehe
[Größe und Profile](groesse.md).

**Rückkehr.** `papaia-ctl doctor model_ready` meldet `pass`.

**Eskalation.** Wie oben; im Archiv stehen die Protokolle von LocalAI und LiteLLM.

## S-3 Anmeldedienst nicht erreichbar

**Anzeichen.** Niemand kann sich anmelden; die Anmeldeseite ist nicht erreichbar.

**Prüfung.** `papaia-ctl doctor container_health identity` meldet „Der Anmeldedienst
(Keycloak) ist nicht erreichbar; niemand kann sich anmelden.“

**Behebung.**

```sh
papaia-ctl logs keycloak --since=30m
papaia-ctl start --profiles=keycloak
```

Läuft die Datenbank `keycloak-postgres` nicht, zuerst [S-4](#s-4-datenbank-eines-moduls-läuft-nicht).

**Rückkehr.** `papaia-ctl doctor identity` meldet `pass`; die Anmeldung geht wieder.

**Eskalation.** Wie oben.

## S-4 Datenbank eines Moduls läuft nicht

**Anzeichen.** Ein Modul zeigt Fehlerseiten oder meldet „nicht verfügbar“; andere Module
melden den Wegfall seiner Funktionen.

**Prüfung.** `papaia-ctl doctor container_health` meldet „Die Datenbank von <Modul> läuft
nicht.“ `papaia-ctl status` nennt den Container.

**Behebung.** Ursache im Protokoll der Datenbank suchen, dann das Modul neu starten:

```sh
papaia-ctl logs <modul> --since=30m
papaia-ctl addon start <modul>          # Modul (Studio, Data, Flow, Assistant, Paperless)
papaia-ctl start --profiles=<profil>    # Kern-Profil, zum Beispiel audit oder me
```

Häufigste Ursache ist eine volle Platte ([S-7](#s-7-kein-platz-auf-der-datenplatte)).

**Rückkehr.** `papaia-ctl status` zeigt das Modul gesund; `papaia-ctl doctor` ohne `fail`.

**Eskalation.** Startet die Datenbank wegen beschädigter Daten nicht, ist eine
[Wiederherstellung](../wiederherstellung.md) des Moduls der nächste Schritt; vorher Archiv aus
`papaia-ctl support-bundle` an den Dienstleister.

## S-5 Not-Aus gesetzt

**Anzeichen.** Kein Modul schreibt, sendet oder löscht mehr; Lesen geht weiter.

**Prüfung.** `papaia-ctl doctor halt` meldet „Die Plattform ist per Not-Aus abgeschaltet
(gesetzt von <Person> um <Zeit>).“ Ist die Not-Aus-Datei nicht lesbar, meldet die Prüfung
„Die Not-Aus-Datei ist nicht lesbar; alle Module gelten als per Not-Aus abgeschaltet.“

**Behebung.** Erst den Grund mit der Person klären, die den Not-Aus gesetzt hat; dann:

```sh
papaia-ctl halt status
papaia-ctl halt clear --reason="<Grund der Aufhebung>"
```

Ein Modul kann zusätzlich einen eigenen Not-Aus haben; er wird in der Verwaltung des Moduls
gesetzt und aufgehoben und erscheint nicht in `papaia-ctl doctor halt`.

**Rückkehr.** `papaia-ctl halt status` zeigt keinen Not-Aus; Setzen und Aufheben stehen im
Audit-Log.

**Eskalation.** Ein Not-Aus ohne bekannten Grund ist ein Sicherheitsvorfall: Audit-Log prüfen
(`papaia-ctl audit verify`) und den Sicherheitsweg oben nutzen.

## S-6 Scope eines Clients fehlt

**Anzeichen.** Zugriffe eines Moduls auf ein anderes werden abgelehnt, obwohl beide laufen.

**Prüfung.** `papaia-ctl doctor realm` meldet „Dem Client <client> fehlt der Scope <scope>;
Zugriffe auf <Modul> werden abgelehnt.“

**Behebung.** Die Einstellungen des Anmeldedienstes aus den Manifesten neu abgleichen:

```sh
papaia-ctl realm sync --check
papaia-ctl realm sync
```

**Rückkehr.** `papaia-ctl realm sync --check` meldet keine Abweichung; `papaia-ctl doctor realm`
meldet `pass`.

**Eskalation.** Wurde der Scope von Hand entfernt, ist die Änderung im Audit-Log des
Anmeldedienstes zu klären; sonst wie oben.

## S-7 Kein Platz auf der Datenplatte

**Anzeichen.** Speichern scheitert in mehreren Modulen; Sicherungen enden mit Fehler.

**Prüfung.** `papaia-ctl doctor disk_space` meldet „Auf <Pfad> ist kein Platz mehr;
Schreiben ist gestoppt.“ oder vorher „Auf <Pfad> wird der Platz knapp; Schreiben kann
jederzeit stoppen.“ `papaia-ctl doctor docker_usage` zeigt, was Docker belegt.

**Behebung.**

```sh
docker system df
papaia-ctl backup-delete --restore-point=<ID>   # nur am Sicherungsziel, alte Punkte
```

Platte vergrößern oder Platz schaffen; nie Volumes von Hand löschen.

**Rückkehr.** `papaia-ctl doctor disk_space` meldet `pass`; danach die Dienste aus
[S-4](#s-4-datenbank-eines-moduls-läuft-nicht) prüfen.

**Eskalation.** Wie oben.

## S-8 Zertifikat abgelaufen

**Anzeichen.** Der Browser warnt vor der Verbindung, oder Dienste mit internem TLS lehnen
Verbindungen untereinander ab.

**Prüfung.** `papaia-ctl doctor certs` meldet „Das Zertifikat für <host> ist seit <Datum>
abgelaufen.“ oder vorher „Das Zertifikat für <host> läuft am <Datum> ab.“

**Behebung.**

```sh
papaia-ctl certs status
papaia-ctl certs renew
```

`certs renew` erneuert die Zertifikate der Plattform-CA. Ein eigenes Zertifikat am Rand (Frage 3
von `setup`) tauscht der Betrieb selbst aus.

**Rückkehr.** `papaia-ctl doctor certs` meldet `pass`.

**Eskalation.** Wie oben.

## S-9 Mailserver nicht erreichbar

**Anzeichen.** Erinnerungen, Freigabe- und Warnmails kommen nicht an. Die Warnmail über diesen
Fehler selbst kann nicht zugestellt werden; er erscheint deshalb nur in `papaia-ctl doctor`
und auf der Seite „Host“ des Managers.

**Prüfung.** `papaia-ctl doctor smtp` meldet „Der Mailserver <host:port> antwortet nicht;
<n> Nachrichten warten.“

**Behebung.** Mailserver und Freigabe in der Firewall prüfen (Matrixzeile K-10 in
[Netz](netz.md)), dann:

```sh
papaia-ctl logs smtp-relay --since=30m
```

Die wartenden Nachrichten sendet das Relais selbst, sobald der Mailserver antwortet.

**Rückkehr.** `papaia-ctl doctor smtp` meldet `pass` und keine wartenden Nachrichten.

**Eskalation.** Wie oben; Zugangsdaten des Mailservers nie in das Archiv oder ein Ticket
schreiben.

## S-10 Datenstand älter als das Löschjournal

**Anzeichen.** Alle Adressen zeigen nach einem Start eine Wartungsseite, oft nach dem
Zurückspielen einer VM- oder Volume-Sicherung (siehe
[Sicherung durch den Hypervisor](sicherung.md#sicherung-durch-den-hypervisor)).

**Prüfung.** `papaia-ctl doctor startgate` und `papaia-ctl status` nennen eine Kennung:

| Kennung | Bedeutung | Handlung |
|---|---|---|
| `CORE-STARTGATE-CHECK` | Die Prüfung nach dem Start läuft. | einige Minuten warten |
| `CORE-STARTGATE-BEHIND` | Der Stand ist älter als das Löschjournal; Kontosperren und Löschungen werden nachgespielt. | das Ende abwarten; die Plattform öffnet danach selbst |
| `CORE-STARTGATE-UNVERIFIED` | Das Löschjournal am Sicherungsziel ist nicht erreichbar; die Plattform bleibt geschlossen. | Sicherungsziel wieder einhängen |
| `CORE-STARTGATE-REPLAY-FAILED` | Das Nachspielen ist für einen Dienst fehlgeschlagen; er bleibt geschlossen. | den Dienst mit `papaia-ctl doctor` prüfen |
| `CORE-STARTGATE-OVERRIDE` | Die Plattform ist ohne Prüfung geöffnet (Übersteuerung durch zwei Personen). | Sicherungsziel wieder einhängen; die Prüfung läuft jede Minute |
| `CORE-STARTGATE-CREDENTIAL-REPLAY` | Konten, deren Zugangsdaten nach dem Sicherungsstand geändert wurden, sind deaktiviert. | Zugangsdaten neu setzen, Konten aktivieren |
| `CORE-STARTGATE-ROLE-REPLAY` | Konten, denen nach dem Sicherungsstand eine Rolle entzogen wurde, sind deaktiviert. | Rollen prüfen, Konten aktivieren |
| `CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR` | Eine Person der Übersteuerung wurde danach gesperrt oder geändert. | mit der zweiten Person prüfen und mit `papaia-ctl startgate acknowledge --reason="<Grund>" --by=<Konto-ID>` bestätigen |
| `CORE-STARTGATE-OVERRIDE-DENIED` | Die Übersteuerung wurde nicht ausgeführt; sie braucht eine zweite Person mit `papaia-admin`. | von einer zweiten Person bestätigen lassen |

Danach meldet `papaia-ctl doctor state_epoch` „Datenstand älter als das Löschjournal (z. B.
nach Rückspielen einer VM-Sicherung). Ausführen: papaia-ctl recover-snapshot“, solange ein
Modul sein Löschjournal noch nicht eingespielt hat.

**Behebung.** Die Startsperre spielt für den Anmeldedienst nach und öffnet selbst; danach
spielt `papaia-ctl recover-snapshot` die Löschjournale der Module ein (Schritt 3 unter
[Sicherung durch den Hypervisor](sicherung.md#sicherung-durch-den-hypervisor)). Ist das
Sicherungsziel dauerhaft verloren, öffnen zwei Personen mit `papaia-admin` ohne Prüfung:

```sh
papaia-ctl startgate open --unverified --reason="<Grund>" \
  --requested-by=<Konto-ID> --confirmed-by=<Konto-ID>
```

Den Ablauf mit frischer Anmeldung beschreibt
[Wiederherstellung](../wiederherstellung.md#zurückgesetzter-server-vm--oder-volume-schnappschuss).

**Rückkehr.** `papaia-ctl doctor startgate` und `papaia-ctl doctor state_epoch` melden `pass`;
danach die Neuerteilung der Vollmachten nach
[Sicherung durch den Hypervisor](sicherung.md#sicherung-durch-den-hypervisor).

**Eskalation.** Bei `CORE-STARTGATE-REPLAY-FAILED` gibt es keine Übersteuerung; den genannten
Dienst lauffähig machen, sonst Archiv aus `papaia-ctl support-bundle` an den Dienstleister.

## Diagnose

Meldet eine Prüfung einen Fehler, den keiner der Abschnitte erklärt, lautet der Satz „Die
Prüfung „<name>“ meldet einen Fehler; die Zeile darüber nennt die Werte.“ Dann:

```sh
papaia-ctl doctor --json              # alle Prüfungen mit Messwerten
papaia-ctl logs <dienst> --since=1h   # Protokoll eines Dienstes oder Moduls
papaia-ctl metrics                    # Messwerte im Textformat
papaia-ctl support-bundle             # Archiv für eine Rückfrage
```

Die Bedeutung jeder Prüfung und ihre Schwellen stehen in der README, Abschnitt `doctor`.
