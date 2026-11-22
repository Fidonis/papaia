# Zuarbeit zur Datenschutz-Folgenabschätzung

Diese Unterlage liefert dem Verantwortlichen die Tatsachen für eine Datenschutz-Folgenabschätzung nach
Art. 35 DSGVO: die Beschreibung der Verarbeitung und eine Liste der Risiken mit Maßnahme und dem
Abnahmekriterium, das die Maßnahme belegt. Die Bewertung der Risiken (Eintrittswahrscheinlichkeit,
Schwere) und die Entscheidung, ob eine Folgenabschätzung nötig ist, trifft der Verantwortliche.

## Beschreibung der Verarbeitung

Die Plattform stellt Beschäftigten Werkzeuge für ihre Arbeit bereit: Chat mit einem Sprachmodell,
Suche in eigenen Dokumenten, Apps aus dem Baukasten (Studio), Auswertungen aus Datenquellen (Data),
automatisierte Abläufe (Flow), eine Assistenz mit Gedächtnis und Erinnerungen (Assistant) und eine
persönliche Übersicht (Mein Bereich). Alle Personen melden sich beim Anmeldedienst der Installation an;
jedes Modul prüft bei jedem Zugriff die Rechte der Person.

Welche Daten je Modul entstehen, wozu, wo sie liegen, wie lange und wie sie gelöscht werden, steht im
Verzeichnis der Verarbeitungstätigkeiten je Modul (Ordner `vvt/`, zum Beispiel
[Kern](vvt/kern.md)), das aus den Erklärungen der Module erzeugt wird. Was protokolliert wird, steht in
[Protokollierung](protokollierung.md).

Die Plattform läuft auf einem Host des Betreibers. Daten verlassen die Installation nur über den
einzigen Ausgang `papaia-egress` an Ziele, die der Betreiber freigegeben hat (OPS-07). Ein Sprachmodell
läuft in der Vorgabe lokal; wird ein Modellserver außerhalb der Installation eingetragen, nennt die
Unterlage der Installation (`papaia-ctl privacy-pack --installation`) ihn als Empfänger.

## Risiken, Maßnahmen, Belege

| Risiko | Maßnahme | Kriterium |
|---|---|---|
| Das Gedächtnis der Assistenz speichert Aussagen über Dritte | Rechteetikett je Eintrag, Sperre bei Rechteentzug, Löschen einzeln und gesamt durch die Person, Bestätigung nach 12 Monaten, höchstens 36 Monate | ASS-06, Kriterien von Mein Bereich, E-19 |
| Ein Gruppenraum verrät Inhalte an Mitglieder ohne Recht | geringstes Recht, Platzhalter statt Inhalt für Mitglieder ohne Recht | ASS-21 bis ASS-25, KE-17, KE-18 |
| Die Nutzungsauswertung erlaubt Rückschluss auf Einzelne | Summen erst ab 5 Personen, keine Personenkennung in Messwerten | PLT-64-A3, EXI-PLT-68-A2, EXI-PLT-68-A3 |
| Das Audit wird als Überwachungsinstrument genutzt | Pseudonyme, Namen nur mit Begründung und zweiter Person, Anzeige jeder solchen Abfrage in Mein Bereich | PLT-64-A1, PLT-64-A2 |
| Freies SQL umgeht den Zeilenschutz einer Datenquelle | freies SQL aus; nur Clients von Data; auf Objekten mit nativer Richtlinie nur die Prädikatform, am Server durchgesetzt | OPS-23, GV-11 |
| Ein Modellanbieter erhält Inhalte | Gateway ohne Speicherung der Eingaben; Modell in der Vorgabe lokal; ein externes Testmodell nur im Teststapel; ein Modellserver des Betreibers außerhalb des Netzes steht als Empfänger in der Unterlage der Installation | EXI-PLT-68-A4, PLT-62 |
| Föderation: falsche Rechte durch zu viele Gruppen beim vorgelagerten Anbieter | die Anmeldung scheitert, statt Gruppen abzuschneiden | GV-33 |
| Der Betreiber mit Host-Zugriff liest Rohdaten | organisatorische Maßnahme, Protokoll der Host-Zugriffe beim Betreiber ([Restwege](keine-leistungskontrolle.md#restwege)) | GV-27 |

## Was der Verantwortliche ergänzt

- Bewertung jedes Risikos für die eigene Installation.
- Zweck und Rechtsgrundlage je Verarbeitung (die Verzeichnisse enthalten dafür Felder mit einem
  Vorschlag der Module).
- Die organisatorischen Maßnahmen, die nur der Betreiber treffen kann ([TOM](tom.md), Zeilen
  „Betreiber“).
- Die Entscheidung, ob eine Folgenabschätzung nötig ist, und deren Ergebnis.
