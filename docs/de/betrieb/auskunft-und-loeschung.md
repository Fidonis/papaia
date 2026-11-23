# Auskunft und Löschung ohne Konto

Dieses Dokument beschreibt, wie der Betrieb einer Person Auskunft gibt oder ihre Daten löscht,
wenn ihr Konto deaktiviert oder gelöscht ist und sie Mein Bereich nicht mehr erreicht. Die
technischen Einzelheiten stehen in [Information and erasure without an account](../../person-requests.md).

## Voraussetzungen

- Die Identität der anfragenden Person ist geprüft (Sache des Betriebs).
- Ihre Kennung (`sub`) ist bekannt, zum Beispiel aus dem Berechtigungsbericht oder aus der
  Kontoverwaltung, solange das Konto besteht.
- Eine zweite Person hat den Antrag bestätigt (Vier-Augen-Prinzip). In dieser Version ist die
  Bestätigung ein organisatorischer Schritt; die Bestätigung im Manager mit frischer Anmeldung
  folgt.
- Für die Löschung: Profil `lifecycle` aktiv (Installationsschlüssel `erasure-hmac`) und das
  Sicherungsziel eingehängt (Ordner `erasure-journal`).
- Die Installation läuft auf einem Host.

## Auskunft

1. Die anfragende Person (oder der Betrieb für sie) erzeugt ein age-Schlüsselpaar und gibt
   nur den öffentlichen Schlüssel (`age1…`) weiter.
2. Auf dem Host:

   ```sh
   papaia-ctl person export --sub=<sub> --out=/pfad/auskunft.zip.age --recipient=<age1…>
   ```

3. Die Ausgabe nennt je Zeile des Verzeichnisses der Verarbeitungstätigkeiten „included“ oder
   „not included“ mit Grund. Exit 1 heißt: Das Archiv ist geschrieben, aber ein Modul fehlt; der
   Grund steht in `index.json` und in der Ausgabe.
4. Archiv und privaten Schlüssel auf zwei getrennten Wegen an die Person übergeben. Wer beides in
   der Hand hat, kann das Archiv lesen. Das Archiv nach bestätigter Übergabe löschen.

Das Archiv hat dasselbe Format wie der Export aus Mein Bereich (`index.json`, je Modul
`<modul>.json` und `<modul>.schema.json`, `LIESMICH.txt`).

## Löschung

1. Auf dem Host, mit Übergabe der Objekte der Person an eine benannte Person:

   ```sh
   papaia-ctl person erase --sub=<sub> --now --transfer-to=<sub der neuen Eigentümerin>
   ```

   Ohne `--transfer-to` bleiben eigene Objekte mit dem Kennzeichen „Eigentümer nicht mehr aktiv“
   stehen und laufen nicht unter der Identität der Person weiter.
2. Scheitert eine Übergabe, wird nichts gelöscht (Exit 1). Scheitert die Löschung in einem
   Modul, löschen die anderen trotzdem; der Vorgang steht auf „partial“ (Exit 1) und wird nach
   Behebung wiederholt.
3. Die Ausgabe ist der Löschnachweis: je Modul und Kategorie die Anzahl gelöschter Einträge und
   ob der Eintrag im Löschjournal am Sicherungsziel liegt („pending“: noch nicht am Ziel, das
   Modul liefert ihn nach), oder bei Daten mit Aufbewahrungspflicht bzw. Löschsperre das Datum,
   bis zu dem sie bleiben. Den Nachweis in der Betriebsablage aufbewahren.

Jeder Aufruf eines Moduls steht im Audit-Log (ohne Inhalte), mit der Kennung der Person und dem
Host-Konto, das den Befehl ausgeführt hat.

## Sicherungen

Eine Löschung wirkt in den Sicherungen erst, wenn diese gelöscht werden (nach der Aufbewahrung
von `backup --retention-period-days` bzw. `--keep`, oder mit `backup-delete`). Bis dahin
enthalten ältere Sicherungen die gelöschten Daten noch. Das Löschjournal verhindert ihre
Rückkehr: `restore` und `rollback` spielen vor dem Start jedes Moduls dessen Löschjournal wieder
ein (siehe [Wiederherstellung](../wiederherstellung.md)).

## Noch nicht enthalten

Chat, Modell-Gateway, Anmeldedienst (einschließlich der Löschung des Kontos), `papaia-lifecycle`
und der pseudonyme Auszug aus dem Audit-Log werden als „not included“ gelistet. Antrag mit
Antragskennung, Bestätigung im Manager, Passphrase für das Archiv und `person find` folgen.
