# Nachweis mit dem ausgelieferten Modell

Dieses Dokument beschreibt, wie belegt wird, dass die Module mit einem ausgelieferten lokalen Modell
arbeiten (Anforderung OPS-14, Kriterium EXK-PLT-72-A2), und was der Bericht dazu enthält. Geprüft wird
die Form der Antworten, nicht ihr Inhalt.

## Welches Modell

Der Nachweis läuft mit der kleinsten ausgelieferten Variante, `qwen2.5-1.5b-instruct`
(Qwen2.5-1.5B-Instruct, Q4_K_M, Apache-2.0). Sie läuft ohne Beschleuniger auf jedem Host der
Mindestausstattung. Das Vorgabemodell `qwen2.5-7b-instruct-q4` wird in der Zielumgebung auf amd64
gemessen; seine Werte stehen getrennt im Bericht. Welche Modelle ausgeliefert werden, steht in
[Lizenz und Bezug](lizenz-und-bezug.md#13-modelle), wie sie eingerichtet werden, im
[Modell-Gateway](../../model-gateway.md#default-model).

Einrichten für den Nachweis: `PAPAIA_DEFAULT_MODEL=qwen2.5-1.5b-instruct` in der `.env` setzen und
`papaia-ctl start` ausführen. Kein Modul wird dafür geändert; die Module rufen nur die Aliase
`papaia-chat` und `papaia-structured` auf.

## Ablauf

Je Modul mit Modellzugang (Studio, Data, Flow, Assistant) zwei feste Merkmalsanfragen, jede zehnmal,
über den Schlüssel des Moduls am Modell-Gateway:

1. **Schema.** Die Anfrage gibt ein JSON-Schema mit; die Antwort muss ihm genügen (Alias
   `papaia-structured`).
2. **Werkzeug.** Die Anfrage gibt ein Werkzeug mit; die Antwort muss einen Aufruf dieses Werkzeugs
   enthalten (Alias `papaia-chat`).

Bestanden ist ein Modul, wenn zehn von zehn Antworten je Anfrage formal gültig sind: Schemaprüfung
bestanden bzw. Werkzeugaufruf vorhanden. Als Zeitgrenze gilt die im Modul eingestellte Grenze für eine
Modellanfrage; eine Antwort nach der Grenze zählt als ungültig.

Kann das Modell eine Fähigkeit nicht (zum Beispiel keinen Werkzeugaufruf), muss das Modul das
dokumentierte Ausweichverhalten zeigen: einen modellfreien Weg oder eine verständliche Meldung, nie
einen unbehandelten Fehler. Ein Modul, das nur über das Ausweichverhalten besteht, wird im Bericht so
gekennzeichnet.

## Bericht

Der Bericht enthält je Modul und Anfrage eine Zeile mit diesen Feldern:

| Feld | Inhalt |
|---|---|
| Modul | Studio, Data, Flow oder Assistant |
| Anfrage | Schema oder Werkzeug |
| Modell | Name, Quantisierung und Digest der Modelldatei |
| Zeitgrenze | die im Modul eingestellte Grenze in Sekunden |
| Ergebnis | Zahl der formal gültigen Antworten von zehn |
| Antwortzeiten | Median und längste Antwortzeit in Sekunden |
| Host | Architektur, Kerne, Arbeitsspeicher, Beschleuniger ja/nein |
| Ausweichverhalten | ob und bei welcher Anfrage das Modul darauf ausweicht |

Der Bericht enthält keine Eingaben und keine Antworten des Modells, nur ihre Prüfergebnisse.
