# Protokollierung: was festgehalten wird, wer es liest, wie lange

Diese Unterlage beschreibt in Alltagssprache, welche Ereignisse die Plattform über die Arbeit von
Personen festhält. Sie ist für den Datenschutzbeauftragten und den Betriebsrat geschrieben. Die
technische Beschreibung steht in [Der Audit-Speicher](../../audit.md).

## Was ein Audit-Ereignis ist

Ein Audit-Ereignis hält fest, **dass** etwas geschehen ist, nicht **was** darin stand: wer (als
Kennung der Person), wann, in welchem Modul, welche Art von Handlung (zum Beispiel „Ablauf
gestartet“, „Rolle entzogen“, „Personenfilter bestätigt“), mit welchem Ergebnis und mit einer
Korrelationskennung, die zusammengehörige Schritte verbindet.

Nie im Audit stehen: Inhalte der Arbeit (Titel, Suchtexte, Eingaben und Antworten des Modells,
Formularwerte, Werte aus Datenbankabfragen), Zugangsdaten und Token (PLT-19-A4). Eine Zeile mit solchen
Feldern weist der Audit-Speicher beim Eingang zurück.

## Woher Ereignisse kommen

Jedes Modul, der Manager, der Kontolebenszyklus (`papaia-lifecycle`, auch für Anmelde- und
Verwaltungsereignisse des Anmeldedienstes), der Ausgang (`papaia-egress`), die MCP-Server und
`papaia-ctl` liefern ihre Ereignisse an genau einen Dienst: `papaia-audit`. Kein Modul hat eine eigene
Leseseite für Audit-Ereignisse. Jede Quelle meldet sich mit einem eigenen Zertifikat an; die Quelle
eines Ereignisses steht damit fest und kann nicht von einer anderen Quelle vorgetäuscht werden.

Die Ereignisse einer Quelle bilden eine Kette: Jedes Ereignis trägt den Prüfwert seines Vorgängers.
Stündlich wird der Stand jeder Kette signiert und am Sicherungsziel abgelegt. Eine nachträgliche
Änderung oder Lücke wird damit erkannt und mit dem ersten nicht passenden Ereignis gemeldet.

## Wer liest

| Wer | Was | Wie |
|---|---|---|
| Person mit der Rolle `papaia-auditor` (Audit-Prüfung) | Ereignisse aller Quellen, Personen nur als Pseudonym (`P-` und acht Zeichen) | Manager, Seite „Audit-Log“, oder `papaia-ctl` |
| dieselbe Person mit bestätigtem Personenfilter | Ereignisse einer Person mit Namen, für höchstens 93 Tage Zeitraum, 60 Minuten lang | Antrag mit Begründung, Bestätigung durch eine zweite Person mit derselben Rolle (PLT-64-A2) |
| die betroffene Person | wann ihre Ereignisse mit Personenfilter gelesen wurden, mit Zeit und Rolle, ohne Namen der prüfenden Person | „Mein Bereich → Aktivität“ |
| Betreiber des SIEM, wenn ein Ziel eingetragen ist | die ausgeleiteten Ereignisse | im SIEM des Betreibers, nach dessen Regeln |
| Personen mit Zugriff auf Host, Datenbank oder Sicherung | technisch alles, was gespeichert ist | siehe [Restwege](keine-leistungskontrolle.md#restwege) |

Die Pseudonyme bildet nur `papaia-audit` mit einem eigenen Schlüssel. Ein Pseudonym bleibt für eine
Person gleich, verrät aber ohne bestätigten Personenfilter nicht, wer dahinter steht. Jede Abfrage
mit Personenfilter ist selbst ein Ereignis und erscheint bei der betroffenen Person (EXI-PLT-68-A6).

Gruppieren oder Zählen nach Person bietet die Lese-Schnittstelle nicht an; eine solche Anfrage wird
abgewiesen (GV-03).

## Wie lange

Ereignisse werden `PAPAIA_AUDIT_RETENTION_MONTHS` Monate aufbewahrt: Vorgabe 12, einstellbar von 6 bis
36. Ein täglicher Lauf um 03:30 UTC entfernt ältere Ereignisse und hält jede Entfernung selbst als
Ereignis fest. Länger bleiben nur:

- Ereignisse einer Person unter einer **Löschsperre** (zum Beispiel wegen eines Rechtsstreits). Eine
  Löschsperre setzen und aufheben zwei verschiedene Personen mit Begründung.
- Ereignisse, die ein eingetragenes SIEM-Ziel noch nicht übernommen hat.

Auf Wunsch einer Person werden Audit-Ereignisse nicht vor Ablauf der Frist gelöscht: Sie belegen, wer
was getan hat, auch zum Schutz der Person selbst.

Kopien außerhalb der Plattform (SIEM, Exporte, Postfächer) und deren Fristen liegen in der
Verantwortung des Betreibers.

## Betriebsprotokolle

Neben dem Audit schreiben die Dienste Betriebsprotokolle (Fehler, Start, Gesundheit). Sie dienen der
Fehlersuche, tragen keine Inhalte der Arbeit und keine Eingaben an das Modell (EXI-PLT-68-A4) und
werden von Docker mit Größenbegrenzung und Rotation gehalten (EXK-PLT-68-A1). Lesen kann sie nur, wer
Zugriff auf den Host hat.

## Messwerte

Messwerte (zum Beispiel Zahl der Anfragen je Modul) tragen keine Personenkennung, keinen
Benutzernamen und keine Mailadresse (EXI-PLT-68-A2). Nutzungssummen gibt es nur je Modul und Zeitraum
oder für Gruppen ab 5 Personen (EXI-PLT-68-A3).
