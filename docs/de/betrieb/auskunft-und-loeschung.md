# Auskunft und Löschung ohne Konto

Dieses Dokument beschreibt, wie der Betrieb einer Person Auskunft gibt oder ihre Daten löscht,
wenn ihr Konto deaktiviert oder gelöscht ist und sie Mein Bereich nicht mehr erreicht. Die
technischen Einzelheiten stehen in [Information and erasure without an account](../../person-requests.md).

## Voraussetzungen

- Die Identität der anfragenden Person ist geprüft (Sache des Betriebs), zum Beispiel durch
  Vorlage des Ausweises bei der Personalabteilung, einen Rückruf unter der bekannten
  Telefonnummer oder eine Antwort an die bisher bekannte Mail-Adresse.
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
   „not included“ mit Grund. Chat, Modell-Gateway (Nutzungssumme und Endnutzer-Einträge) und
   Anmeldedienst sind enthalten (für den Anmeldedienst muss das Profil `lifecycle` aktiv
   sein). Die Nutzungszeilen des Modell-Gateways je Anfrage und die Tagessummen je
   Endnutzer sind es nicht (siehe „Noch nicht enthalten“). Exit 1 heißt „teilweise“: ein Modul
   oder Kerndienst fehlt (Auskunft) oder eine Übergabe, Löschung oder der Abgleich scheiterte
   (Löschung). Nach Behebung einen neuen Antrag stellen.

   Reihenfolge einer Löschung: Zuerst wird das Konto deaktiviert, Sitzungen und
   Einwilligungen enden. Dann folgen Übergaben, Module, Chat und Modell-Gateway mit je einem
   Eintrag im Löschjournal (`core-chat`, `model-gateway`). Das Konto wird zuletzt gelöscht.
   Scheitert vorher ein Schritt, bleibt das Konto deaktiviert und wird nicht gelöscht
   („disabled, not deleted“); die Kennung bleibt für einen neuen Antrag zugeordnet.
   Scheitert schon das Deaktivieren, wird nichts gelöscht und das Konto bleibt, wie es ist
   („failed identity/account“). Ohne Profil `lifecycle` wird das Konto vor der Löschung nicht
   deaktiviert; die Ausgabe sagt das in einer Zeile „note“. Dann das Konto im Anmeldedienst
   deaktivieren und einen neuen Antrag stellen.

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
   stehen; scheitert eine Übergabe, wird nichts gelöscht. Am Ende steht der Abgleich: Chat,
   Modell-Gateway und Anmeldedienst werden erneut nach der Kennung, den Chat-Konten und der
   Mail-Adresse der Person gefragt. „reconciliation: nothing of the person left in the places
   checked“ heißt ohne Fund an den abgefragten Stellen; jede Zeile „left“ nennt Ort und
   Anzahl (nie Inhalte) und macht den Antrag „teilweise“. Jede Zeile „not checked“ nennt
   eine Stelle, die der Abgleich nicht abfragt; dort können Daten der Person liegen (siehe
   „Noch nicht enthalten“). Die Zeile „not erased model-gateway/usage_rows“ gehört in den
   Nachweis. Den Nachweis in der Betriebsablage aufbewahren und mit Datum und Kennung in
   die Liste der Löschnachweise eintragen; sie wird gebraucht, wenn von einer älteren Kopie
   wiederhergestellt wird (siehe [Kopien außer Haus](sicherung.md#kopien-außer-haus)).

Die Antwort an die Person ist ohne Verzögerung, spätestens innerhalb eines Monats nach Eingang
der Anfrage fällig (Art. 12 Abs. 3 DSGVO,
<https://eur-lex.europa.eu/eli/reg/2016/679/oj>); der Eingang ist deshalb mit Datum
festzuhalten.

Wer `person export` ausführt und die Passphrase erhält, kann das Archiv lesen. Antrag und
Bestätigung durch zwei Personen machen das sichtbar, verhindern es aber nicht.

Antrag, Bestätigung, jeder Schritt des Laufs, jeder Aufruf eines Moduls und jeder Aufruf
eines Kerndienstes (je Sammlung des Chats eine Zeile mit Anzahl) stehen im Audit-Log (ohne
Inhalte), mit der Antragskennung als Korrelationskennung.

`doctor model_gateway_content` schlägt fehl, wenn das Modell-Gateway Inhalte von Anfragen
oder Antworten speichern würde; die Nutzung, die Auskunft und Löschung erfassen, enthält
dann keine Inhalte.

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

`papaia-lifecycle` (der Grabstein bleibt so lange wie das Löschjournal), der pseudonyme Auszug
aus dem Audit-Log und die Inhalte hochgeladener Chat-Dateien auf dem Datei-Volume samt
Suchindex werden als „not included“ gelistet; die Dateieinträge in der Chat-Datenbank werden
gelöscht. Ebenso gelistet, mit Aufbewahrung:

- Die Nutzungszeilen des Modell-Gateways je Anfrage (`LiteLLM_SpendLogs`) und die
  Tagessummen je Endnutzer (`LiteLLM_DailyEndUserSpend`) mit der Chat-Konto-Kennung der
  Person: Anzahlen und Kosten, keine Inhalte. Sie bleiben, solange die Datenbank des
  Gateways besteht; eine Frist ist nicht eingestellt. Die Löschung über das Gateway entfernt
  nur den Endnutzer-Eintrag. Ein Löschweg für diese Zeilen fehlt, bis er gegengezeichnet ist
  (Nachweis MN-17).
- Die Container-Protokolle von Chat (Kennung, Benutzername und Mail-Adresse bei der
  Anmeldung, dazu die Protokolldateien im Volume `librechat-logs`) und Modell-Gateway
  (Chat-Konto-Kennung): Rotation nach Größe, 5 × 10 MiB je Container, ohne Frist; sie
  verschwinden mit dem Container. Die Seite im Manager zum Bestätigen folgt.
