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
   kommt aus dem Punkt.
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
