# Auskunft und Löschung ohne Konto

Dieses Dokument beschreibt, wie der Betrieb einer Person Auskunft gibt oder ihre Daten löscht,
wenn ihr Konto deaktiviert oder gelöscht ist und sie Mein Bereich nicht mehr erreicht. Die
technischen Einzelheiten stehen in [Information and erasure without an account](../../person-requests.md).

## Voraussetzungen

- Die Identität der anfragenden Person ist geprüft (Sache des Betriebs).
- Zwei Personen sind beteiligt: eine stellt den Antrag (`--requested-by`), eine zweite
  bestätigt ihn im Manager (`--confirmed-by`, Rolle `papaia-confirm` oder `papaia-admin`).
  Dieselbe Person kann ihren eigenen Antrag nicht bestätigen.
- Profile `audit` (Antragsablage) und `lifecycle` (Suche, Installationsschlüssel
  `erasure-hmac`) aktiv; für die Löschung zusätzlich das Sicherungsziel eingehängt (Ordner
  `erasure-journal`).
- Die Installation läuft auf einem Host.

## Ablauf in sechs Schritten

1. **Person finden.** Ist die Kennung (`sub`) nicht bekannt, sucht der Betrieb nach
   Benutzername oder Mail-Adresse, auch für gelöschte Konten:

   ```sh
   papaia-ctl person find --email=anna.berger@example.org
   ```

   Die Eingabe wird auf dem Host gehasht (HMAC), `papaia-lifecycle` kennt nur Hashes. Die
   Ausgabe nennt Kennung, Status (`active`, `disabled`, `deleted`) und Tage, nie einen Namen.

2. **Antrag stellen.** Auskunft oder Löschung:

   ```sh
   papaia-ctl person export --sub=<sub> --requested-by=<sub Antragsteller> --confirmed-by=<sub Bestätiger>
   papaia-ctl person erase  --sub=<sub> --now --requested-by=<sub> --confirmed-by=<sub> \
       [--transfer-to=<sub der neuen Eigentümerin>]
   ```

   Die Ausgabe nennt die Antragskennung. Es läuft noch nichts.

3. **Bestätigen.** Die zweite Person meldet sich im Manager neu an (höchstens 5 Minuten
   vorher) und bestätigt oder lehnt ab. Bei einer Auskunft zeigt der Manager ihr **einmal**
   eine Passphrase; sie wird nirgends gespeichert. Ein offener Antrag verfällt nach 7 Tagen.

4. **Ausführen.** Innerhalb von 24 Stunden nach der Bestätigung:

   ```sh
   papaia-ctl person status <antrag>
   papaia-ctl person run <antrag>
   ```

   Die Ausgabe nennt je Zeile des Verzeichnisses der Verarbeitungstätigkeiten „included“ oder
   „not included“ mit Grund. Exit 1 heißt „teilweise“: ein Modul fehlt (Auskunft) oder eine
   Übergabe bzw. Löschung scheiterte (Löschung). Nach Behebung einen neuen Antrag stellen.

5. **Übergeben (Auskunft).** Das Archiv liegt in
   `<config-dir>/state/person-export/<antrag>.zip.age`. Archiv und Passphrase gehen auf
   **zwei getrennten Wegen** an die Person (`age -d` öffnet es mit der Passphrase). Danach:

   ```sh
   papaia-ctl person handover <antrag>
   ```

   Spätestens nach 14 Tagen wird das Archiv gelöscht (`papaia-ctl person sweep`, läuft auch
   vor jedem anderen `person`-Befehl); `doctor person_export` warnt, solange eines wartet.

6. **Nachweis ablegen (Löschung).** Die Ausgabe von `person run` ist der Löschnachweis: je
   Modul und Kategorie die Anzahl gelöschter Einträge und ob der Eintrag im Löschjournal am
   Sicherungsziel liegt („pending“: noch nicht am Ziel, das Modul liefert ihn nach), oder bei
   Daten mit Aufbewahrungspflicht bzw. Löschsperre das Datum, bis zu dem sie bleiben. Ohne
   `--transfer-to` bleiben eigene Objekte mit dem Kennzeichen „Eigentümer nicht mehr aktiv“
   stehen; scheitert eine Übergabe, wird nichts gelöscht. Den Nachweis in der Betriebsablage
   aufbewahren.

Antrag, Bestätigung, jeder Schritt des Laufs und jeder Aufruf eines Moduls stehen im
Audit-Log (ohne Inhalte), mit der Antragskennung als Korrelationskennung.

## Namenssperre

Legt jemand ein Konto mit dem Benutzernamen oder der Mail-Adresse eines gelöschten Kontos an,
deaktiviert `papaia-lifecycle` das neue Konto einmal und meldet es (`ALERT`). So übernimmt
niemand über den Namen die Daten der früheren Person. Nach Prüfung aktiviert die Verwaltung
das Konto wieder; es wird nicht erneut gesperrt.

## Sicherungen

Eine Löschung wirkt in den Sicherungen erst, wenn diese gelöscht werden (nach der Aufbewahrung
von `backup --retention-period-days` bzw. `--keep`, oder mit `backup-delete`). Bis dahin
enthalten ältere Sicherungen die gelöschten Daten noch. Das Löschjournal verhindert ihre
Rückkehr: `restore` und `rollback` spielen vor dem Start jedes Moduls dessen Löschjournal wieder
ein (siehe [Wiederherstellung](../wiederherstellung.md)).

## Noch nicht enthalten

Chat, Modell-Gateway, Anmeldedienst (einschließlich der Löschung des Kontos), `papaia-lifecycle`
und der pseudonyme Auszug aus dem Audit-Log werden als „not included“ gelistet. Die Seite im
Manager zum Bestätigen folgt.
