# Wiederherstellung aus einer Sicherung

Kurzanleitung für den Betrieb. Die vollständige Beschreibung der Schalter steht im README,
Abschnitt `restore`.

## Ablauf

1. Sicherungsziel einhängen und den Punkt wählen: `tools/papaia-ctl restore --from=<Ziel> --list`.
2. Wiederherstellen, den Sicherungsschlüssel auf der Standardeingabe:

   ```bash
   tools/papaia-ctl restore --from=<Ziel> --restore-point=<ID> --identity=- -y
   ```

   Ohne `--from` gilt das in der Einrichtung angegebene Sicherungsziel.

   Schlüssel einfügen, dann Strg-D. Alternativ `--identity=<Schlüsseldatei>`; eine durch
   Kennsatz geschützte Datei fragt den Kennsatz einmal ab. Der Schlüssel wird nicht auf die
   Platte geschrieben und erscheint in keinem Protokoll.
3. `tools/papaia-ctl doctor` prüfen.

Ohne Schlüssel bricht `restore` mit Ausgang 2 und der Meldung „The key for restore point
<ID> is missing (recipients: …)“ ab, bevor etwas geändert wird. Ein Schlüssel, der kein
Empfänger des Punkts ist, oder ein verändertes Archiv führt ebenso zum Abbruch ohne Änderung.

Jeder Punkt trägt neben den verschlüsselten Archiven die unverschlüsselte Datei
`<Ziel>/<Punkt>/RELEASE` mit Kern-Tag, Suite-Version und Installations-ID, ohne Personendaten
und ohne Schlüssel. `<Ziel>/latest/RELEASE` ist die Datei des jüngsten vollständigen Punkts mit
Ergebnis `ok`, `<Ziel>/latest/POINT` nennt dessen ID. Passt der Checkout nicht zum Tag des
Punkts, bricht `restore` vor jeder Änderung mit Ausgang 2 ab und nennt den Befehl, etwa
`git checkout v1.10.0`.

## Wiederherstellung nach Verlust des Hosts

Übrig sind nur das Sicherungsziel und ein Sicherungsschlüssel.

Vorarbeiten: neuer Host mit Docker, Sicherungsziel einhängen, DNS auf die neue Adresse (entfällt
bei gleicher Adresse).

1. Tag lesen: `<Ziel>/latest/RELEASE` mit einem Texteditor oder Dateibrowser öffnen, Zeile `tag:`.
   Dafür ist kein `papaia-ctl` nötig.
2. Kern holen: `git clone --branch <Tag> https://github.com/Fidonis/papaia.git`. Die Add-ons an
   den Pfaden bereitstellen, die die Installation benutzt hat (`addons` in
   `<Ziel>/<Punkt>/manifest.yaml`).
3. Im Checkout:

   ```bash
   tools/papaia-ctl restore --from=<Ziel> --restore-point=latest --identity=- -y
   ```

   Schlüssel einfügen, dann Strg-D. Ein vorheriges `setup` ist nicht nötig: die Konfiguration
   kommt aus dem Punkt. Im neuen Checkout baut `restore` zuerst die Laufzeitumgebung von
   `papaia-ctl` (`tools/.runtime/`); dafür braucht es den Paketindex oder einen Spiegel
   (`PIP_INDEX_URL`, `PIP_FIND_LINKS`).
4. `tools/papaia-ctl doctor`.

Ohne Einrichtung verlangt `restore` den Schalter `--from` und stellt nur den ganzen Punkt
wieder her (kein `--only`). Das Ziel muss die Kennungsdatei `.papaia-target` tragen; ein Punkt,
dessen `RELEASE` eine andere Installation nennt als das Ziel, wird abgewiesen.

Gleich bleiben müssen Basis-Domain, App-Domain und Aussteller-URL der Anmeldung, also die
Hostnamen der Installation. Das TLS-Material kommt aus dem Punkt. Abweichende Namen unterstützt
dieser Ablauf nicht, denn die Konfiguration aus dem Punkt trägt die alten Namen: DNS-Einträge
auf den neuen Host zeigen lassen.

Die Wiederherstellungszeit wird vom ersten Befehl bis `doctor` ohne Fehler gemessen; Ziel sind
höchstens 60 Minuten.

## Was nach dem Zurückspielen geschieht

- **Löschungen bleiben gelöscht.** Vor dem ersten Start jedes Moduls spielt `restore` dessen
  Löschjournal am Sicherungsziel ein (Modulaktion `erasure-replay`), danach den Schritt
  `post-restore` der Vollmachtshalter. Erst dann startet das Modul. Scheitert ein Schritt,
  bleibt das Modul aus; der nächste `start --addons` oder `addon start <name>` wiederholt den
  Schritt zuerst.
- **Jedes Modul schreibt nur sein eigenes Löschjournal.** Ein Modul sieht am Sicherungsziel
  nur seine eigene Datei `erasure-journal/<modul>.jsonl`; `epoch`, die Journale des Kerns und
  die anderer Module erreicht es nicht. So kann kein Modul Einträge eines anderen entfernen
  oder ihm eine Löschung unterschieben. `papaia-ctl doctor erasure_journal` meldet `fail`,
  wenn ein Container außer `papaia-lifecycle` den Ordner, das Sicherungsziel oder eine fremde
  Datei beschreiben kann, wenn eine Datei ein Verweis ist, einen zweiten Namen hat, einem
  anderen Konto gehört oder von anderen beschreibbar ist, und wenn in einem Journal eine Zeile
  eines anderen Moduls steht. Ein solches Journal spielt das Modul nicht ein: Herkunft der
  Zeile klären, erst dann die Zeile entfernen.
- **Vollmachten sind ungültig.** Die Vollmachtsschlüssel liegen nicht in der Sicherung;
  Anmeldedienst und Module beenden die alten Sitzungen und Vollmachten. Die Personen erteilen
  ihre Vollmachten neu.
- **Löschprobe.** Nach dem Start der Module prüft `restore`, dass seit dem Punkt Gelöschtes
  nicht zurückgekehrt ist. Für jedes Löschjournal am Ziel zählen die Einträge ab dem Zeitpunkt
  des Punkts. Ein Modul besteht, wenn sein `erasure-replay` in diesem Restore mit Ausgang 0 im
  Audit steht und nichts mehr fällig ist. Es fällt durch, wenn kein installiertes Add-on das
  Journal einspielt, das Add-on kein `erasure-replay` kennt, das Einspielen fehlte oder
  scheiterte oder das Journal unlesbar ist. Die Ausgabe nennt je Modul `pass`, `fail` oder
  `core` (Journale des Kerns: Konten, Chat, Modell-Gateway; die spielt der Kern selbst ein).
  Fällt die Probe durch, endet `restore` mit Ausgang 3; `backup.log` zeigt
  `erasure_probe=fail`, das Audit den Eintrag `erasure_probe`. Mit `--no-restart` läuft die
  Probe nicht.
- **Dauer.** `restore` gibt „Restore took N s“ aus und schreibt die Dauer in `backup.log`
  (`duration=`) und in das Audit (`restore_applied`, `duration_s`). Das ist die gemessene
  Wiederherstellungszeit; Ziel sind höchstens 60 Minuten.

## Zurückgesetzter Server (VM- oder Volume-Schnappschuss)

Mit dem Profil `lifecycle` hält `papaia-lifecycle` nach jedem Start den Zugang über den
Proxy geschlossen, bis sein Stand nicht älter ist als das Löschjournal am Sicherungsziel.
Die Nutzenden sehen bis dahin eine Wartungsseite; die Verwaltung des Proxys bleibt
erreichbar. Ist der Stand älter (ein zurückgesetzter Schnappschuss), spielt der Dienst
Kontosperren, Löschungen und entzogene Rechte nach, meldet alle Personen ab und öffnet
danach. Löschungen in Chat und Modell-Gateway (Gespräche und Konto einer gelöschten
Person, gespeicherte Chat-Sitzungen, widerrufene Modulschlüssel) führt dabei der Dienst
`papaia-replay` aus; er erhält Aufträge nur von `papaia-lifecycle` und meldet nur
Anzahlen zurück ([replay.md](../replay.md)). Er braucht die Rolle `papaia-replay-chat` in
der Chat-Datenbank, die `papaia-ctl start` anlegt. Meldet `start` „The chat role of
papaia-replay could not be set up“, `papaia-ctl start` wiederholen, sobald die
Chat-Datenbank läuft; bis dahin bleibt ein Rückstand im Chat geschlossen. `papaia-ctl doctor startgate` zeigt den Zustand mit einer Kennung:

| Kennung | Bedeutung | Was tun |
|---|---|---|
| `CORE-STARTGATE-CHECK` | Die Prüfung nach dem Start läuft. | Einige Minuten warten. |
| `CORE-STARTGATE-BEHIND` | Der Stand ist älter als das Löschjournal; es wird nachgespielt. | Das Ende abwarten; der Zugang öffnet danach selbst. |
| `CORE-STARTGATE-UNVERIFIED` | Das Löschjournal am Sicherungsziel ist nicht erreichbar. | Das Sicherungsziel wieder einhängen; die Prüfung läuft jede Minute. |
| `CORE-STARTGATE-REPLAY-FAILED` | Das Nachspielen ist für einen Teil fehlgeschlagen; dieser Teil bleibt geschlossen. | Den genannten Teil mit `papaia-ctl doctor` prüfen. |
| `CORE-STARTGATE-CREDENTIAL-REPLAY` | Konten, deren Zugangsdaten nach dem Schnappschuss geändert wurden, sind deaktiviert. | Zugangsdaten neu setzen und die Konten aktivieren. |
| `CORE-STARTGATE-ROLE-REPLAY` | Konten, denen nach dem Schnappschuss eine Rolle entzogen wurde, sind deaktiviert. | Rollen prüfen und die Konten aktivieren. |

Ist das Sicherungsziel dauerhaft verloren (`CORE-STARTGATE-UNVERIFIED`), öffnen zwei
Personen mit `papaia-admin` den Zugang ohne Prüfung. Bei einem fehlgeschlagenen
Nachspielen (`CORE-STARTGATE-REPLAY-FAILED`) gibt es keine Übersteuerung; dort hilft nur,
den genannten Teil wieder lauffähig zu machen.

1. Die bestätigende Person meldet sich frisch über den Verwaltungsweg an: Sie öffnet die
   Verwaltung des Proxys (`NPM_ADMIN_HOST`, zum Beispiel `https://npm.example.org`) und
   meldet sich dort an. Diese Anmeldung beim Anmeldedienst ist auch bei geschlossenem
   Zugang möglich; alles andere auf dem Anmeldedienst und auf den übrigen Adressen bleibt
   gesperrt. Ohne Mitgliedschaft in `npm-admin` endet die Anmeldung auf einer Fehler- oder
   Wartungsseite; die Anmeldung zählt trotzdem.
2. Innerhalb von 5 Minuten danach:

```sh
papaia-ctl startgate open --unverified --reason="Sicherungsplatte getauscht" \
  --requested-by=<Konto-ID> --confirmed-by=<Konto-ID>
```

Eine Person allein genügt nur, wenn das Vier-Augen-Prinzip ausgeschaltet ist, nie im Profil
`kritis`. Die Übersteuerung steht im Audit und geht per Mail an die Betriebsadresse; sie
endet, sobald das Sicherungsziel wieder erreichbar ist.

Wird eine der beiden Personen danach gesperrt oder geändert
(`CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR`), meldet `papaia-ctl doctor startgate` einen
Fehler, bis eine andere Person mit `papaia-admin` die Prüfung bestätigt. Sie meldet sich
dazu ebenfalls frisch über den Verwaltungsweg an:

```sh
papaia-ctl startgate acknowledge --reason="Übersteuerung mit der Betriebsadresse geprüft" \
  --by=<Konto-ID>
```

### Nach dem Zurückspielen: `recover-snapshot`

Eine VM- oder Volume-Sicherung des Hypervisors ist zulässig, ersetzt aber `backup` nicht. Sie
enthält Vollmachts- und Rückwegschlüssel: verschlüsselt ablegen und nicht länger aufbewahren
als die Sicherungspunkte. Nach jedem Zurückspielen, bevor die Personen wieder arbeiten:

1. VM starten. Die Startsperre hält die Plattform geschlossen und spielt Kontosperren und
   Löschungen nach (siehe oben).
2. `papaia-ctl doctor` zeigt `state_epoch` mit `fail` oder `warn` und den Zustand von
   `startgate`.
3. `papaia-ctl recover-snapshot`.
4. `papaia-ctl doctor` endet mit Ausgang 0.
5. Den Personen den Mustertext zur Neuerteilung ihrer Vollmachten senden.

`recover-snapshot` braucht keinen Betreiberschlüssel und fragt nichts. Es

- übernimmt Einträge, die nur der Spiegel des Löschjournals hat, an das Sicherungsziel
  (siehe „Kopien außer Haus“),
- löscht alle Rückwegschlüssel unter `state/rollback/`; sie stammen aus dem Schnappschuss.
  Ein Rückweg nach einem Upgrade geht danach nur noch mit `--identity`,
- setzt im Anmeldedienst realmweit „not before“ und entfernt die Einwilligungen der
  Vollmachtshalter (Schritt `post-restore` des Kerns),
- hält jedes Add-on an und startet es erst wieder, nachdem es sein Löschjournal eingespielt
  (`erasure-replay`, auch Widerrufe von Vollmachten) und seinen Schritt `post-restore`
  ausgeführt hat,
- gibt je Add-on die Zahl der nachgeholten Löschungen und Widerrufe aus, schreibt einen
  Audit-Eintrag (`recover_snapshot`) und eine Zeile `recover` in `backup.log`,
- endet mit `papaia-ctl doctor` und dessen Ausgang.

Scheitert das Einspielen eines Add-ons, bleibt es aus, `recover-snapshot` endet mit Ausgang 3,
und ein erneuter Aufruf wiederholt die offenen Schritte. Ist das Löschjournal am
Sicherungsziel oder der Spiegel nicht erreichbar, ändert `recover-snapshot` nichts und endet
mit Ausgang 3. Einspielen geschieht nur über `restore`, `rollback` und `recover-snapshot`;
`addon run` bietet die Schritte nicht an.

`doctor state_epoch`:

| Ergebnis | Bedeutung | Was tun |
|---|---|---|
| `fail` | Ein Add-on hat sein Löschjournal noch nicht eingespielt, die Startsperre ist im Rückstand oder ihr Nachspielen scheiterte, oder `epoch` am Ziel ist beschädigt. Satz: „Datenstand älter als das Löschjournal (z. B. nach Rückspielen einer VM-Sicherung). Ausführen: papaia-ctl recover-snapshot“. | `papaia-ctl recover-snapshot`; bei beschädigtem `epoch` das Sicherungsziel prüfen. |
| `warn` | Das Löschjournal am Ziel oder der Spiegel ist nicht erreichbar (die Prüfung ist dann nur vorläufig), oder die Startsperre hat nach einem Schnappschuss nachgespielt und `recover-snapshot` steht noch aus. | Ziel bzw. Spiegel einhängen; `papaia-ctl recover-snapshot`. |
| `pass` | Kein Add-on und kein Kerndienst steht hinter dem Löschjournal. | – |

## Kopien außer Haus

Eine Kopie des Sicherungsziels außer Haus trägt ein Löschjournal, das mit dem Tag der Kopie
endet. Deshalb wird das Löschjournal zusätzlich an eine zweite Ablage gespiegelt, die Sie
angeben, am besten Speicher außer Haus, der nur Anhängen erlaubt:

```sh
papaia-ctl backup mirror --erasure-mirror=/mnt/offsite/papaia-loeschjournal \
  --offsite-retention=180
```

- `--erasure-mirror` ist ein eingehängter Ordner außerhalb des Sicherungsziels; `none`
  entfernt den Spiegel. Der Ordner wird nie angelegt: ein nicht eingehängter Spiegel gilt als
  nicht erreichbar, nicht als leer.
- `--offsite-retention` ist die längste Zeit, die Sie eine Kopie außer Haus aufbewahren, in
  Tagen (0 bis 3650, Vorgabe 90).
- Ohne Werte zeigt `papaia-ctl backup mirror` die Einstellung.

Jedes `backup` hängt an den Spiegel an, was das Journal am Ziel hat und der Spiegel nicht. Ist
der Spiegel nicht erreichbar, endet die Sicherung mit `partial`. `restore` und
`recover-snapshot` lesen Ziel und Spiegel und spielen die Vereinigung ein (Entdoppelung über
die Folgenummer je Modul). Der Spiegel behält jeden Eintrag, bis er älter ist als der älteste
Sicherungspunkt plus 30 Tage und älter als die Aufbewahrung außer Haus plus 30 Tage; das
Löschjournal am Ziel räumen die Module selbst auf.

Ohne Spiegel gibt `restore` diesen Satz aus, und er gilt: „Wird von einer Kopie außer Haus
wiederhergestellt, kehren Löschungen nach dem Tag dieser Kopie zurück. Führen Sie danach für
jede Person aus der Liste der Löschnachweise seit diesem Tag `person erase` erneut aus.“

## Rückweg nach einem Upgrade

Jedes Upgrade erzeugt in Stufe 0 einen einmaligen Rückwegschlüssel. Der Wiederherstellungspunkt
R0 ist an die Sicherungsempfänger und an diesen Schlüssel verschlüsselt. Der private Teil liegt
nur auf dem Host (`state/rollback/<upgrade-id>.key`, Ordner `0700`, Datei `0600`) und nie am
Sicherungsziel.

- **Ein Befehl.** Scheitert das Upgrade, nennt die Ausgabe `tools/papaia-ctl rollback -y`. Der
  Befehl wechselt den Checkout auf die Ausgangsversion, spielt R0 mit `--restart-clean` zurück
  (Löschjournale und `post-restore` laufen vor dem Start der Module), hebt die Schreibsperre
  auf, löscht den Rückwegschlüssel und endet mit `doctor`. Ein Betreiberschlüssel ist dafür
  nicht nötig.
- **Frist.** Nach einem erfolgreichen Upgrade bleibt der Schlüssel 72 Stunden
  (`PAPAIA_ROLLBACK_WINDOW_HOURS`, 24 bis 168). `tools/papaia-ctl upgrade --finalize -y` löscht
  ihn früher. `tools/papaia-ctl doctor rollback_window` zeigt die Restzeit und meldet `fail`,
  wenn ein Schlüssel nach Fristende noch vorhanden ist. Die geplante Sicherung entfernt
  abgelaufene Schlüssel.
- **Nach der Frist** verlangt `rollback` den Sicherungsschlüssel eines Empfängers
  (`--identity=<Datei>` oder `--identity=-` mit `-y`). Er wird vor jeder Änderung gegen alle
  Archive von R0 geprüft.
- **Datenverlust.** War das Upgrade schon abgeschlossen, hat die Installation seither
  Änderungen angenommen; sie gehen verloren. `rollback` sagt das und verlangt
  `--accept-data-loss` oder die Eingabe „ja“; `-y` ersetzt diese Bestätigung nicht.
- **Ohne Rückwegschlüssel** (`upgrade --no-rollback-key`) prüft Stufe 0 des Upgrades den
  Sicherungsschlüssel (`--identity`) und bricht ohne passenden Schlüssel ab: „Without a
  matching backup key there is no way back; the upgrade was not started.“

## Probewiederherstellung neben dem laufenden Stapel

Eine Probe läuft in einer zweiten Installation mit eigener Docker-Engine (zweiter Host oder
virtuelle Maschine), nie in derselben Engine wie das Original: `restore` schreibt die Volumes
unter den Namen aus dem Punkt und übernimmt dessen Konfiguration. In der zweiten Installation
`setup` ohne `start`, dann `restore --from=<Kopie des Sicherungsziels>` wie oben und
`doctor`. Die Zeit vom Befehl `restore` bis `doctor` ohne Fehler ist die gemessene
Wiederherstellungszeit.
