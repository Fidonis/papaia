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

## Probewiederherstellung neben dem laufenden Stapel

Eine Probe läuft in einer zweiten Installation mit eigener Docker-Engine (zweiter Host oder
virtuelle Maschine), nie in derselben Engine wie das Original: `restore` schreibt die Volumes
unter den Namen aus dem Punkt und übernimmt dessen Konfiguration. In der zweiten Installation
`setup` ohne `start`, dann `restore` wie oben mit einer Kopie des Sicherungsziels und
`doctor`. Die Zeit vom Befehl `restore` bis `doctor` ohne Fehler ist die gemessene
Wiederherstellungszeit.
