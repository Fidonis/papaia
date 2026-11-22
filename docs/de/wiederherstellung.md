# Wiederherstellung aus einer Sicherung

Kurzanleitung für den Betrieb. Die vollständige Beschreibung der Schalter steht im README,
Abschnitt `restore`.

## Ablauf

1. Sicherungsziel einhängen und den Punkt wählen: `tools/papaia-ctl restore --list`.
2. Wiederherstellen, den Sicherungsschlüssel auf der Standardeingabe:

   ```bash
   tools/papaia-ctl restore --restore-point=<ID> --identity=- -y
   ```

   Schlüssel einfügen, dann Strg-D. Alternativ `--identity=<Schlüsseldatei>`; eine durch
   Kennsatz geschützte Datei fragt den Kennsatz einmal ab. Der Schlüssel wird nicht auf die
   Platte geschrieben und erscheint in keinem Protokoll.
3. `tools/papaia-ctl doctor` prüfen.

Ohne Schlüssel bricht `restore` mit Ausgang 2 und der Meldung „The key for restore point
<ID> is missing (recipients: …)“ ab, bevor etwas geändert wird. Ein Schlüssel, der kein
Empfänger des Punkts ist, oder ein verändertes Archiv führt ebenso zum Abbruch ohne Änderung.

## Was nach dem Zurückspielen geschieht

- **Löschungen bleiben gelöscht.** Vor dem ersten Start jedes Moduls spielt `restore` dessen
  Löschjournal am Sicherungsziel ein (Modulaktion `erasure-replay`), danach den Schritt
  `post-restore` der Vollmachtshalter. Erst dann startet das Modul. Scheitert ein Schritt,
  bleibt das Modul aus; der nächste `start --addons` oder `addon start <name>` wiederholt den
  Schritt zuerst.
- **Vollmachten sind ungültig.** Die Vollmachtsschlüssel liegen nicht in der Sicherung;
  Anmeldedienst und Module beenden die alten Sitzungen und Vollmachten. Die Personen erteilen
  ihre Vollmachten neu.
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
`setup` ohne `start`, dann `restore` wie oben mit einer Kopie des Sicherungsziels und
`doctor`. Die Zeit vom Befehl `restore` bis `doctor` ohne Fehler ist die gemessene
Wiederherstellungszeit.
