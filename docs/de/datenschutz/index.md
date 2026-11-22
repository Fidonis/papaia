# Datenschutzunterlagen der Plattform

Diese Unterlagen sind für den Datenschutzbeauftragten, den Betriebsrat und den Verantwortlichen im
Sinne der DSGVO geschrieben. Sie beschreiben, welche personenbezogenen Daten die Plattform verarbeitet,
was protokolliert wird, wer was lesen kann und welche Maßnahmen die Daten schützen. Sie sind Teil der
Lieferung und mit dem Kern versioniert; es gilt die Fassung der installierten Version.

**Hinweis:** Die Unterlagen liefern Tatsachen und Vorlagen. Die rechtliche Prüfung und die
Entscheidungen (Rechtsgrundlage, Folgenabschätzung, Betriebsvereinbarung) trifft der Verantwortliche.

## Unterlagen

| Unterlage | Inhalt |
|---|---|
| [Verzeichnis der Verarbeitungstätigkeiten, Kern](vvt/kern.md) | Vorlage nach Art. 30 DSGVO, erzeugt aus den Erklärungen der Module; je Modul eine Datei im Ordner `vvt/` |
| [Protokollierung](protokollierung.md) | was protokolliert wird, wer es liest, wie lange |
| [Keine Leistungs- oder Verhaltenskontrolle](keine-leistungskontrolle.md) | Begründung mit Kriterien, Restwege, Satz für die Betriebsvereinbarung |
| [Zuarbeit zur Datenschutz-Folgenabschätzung](dsfa-zuarbeit.md) | Beschreibung der Verarbeitung, Risiken mit Maßnahme und Beleg |
| [Technische und organisatorische Maßnahmen](tom.md) | Maßnahmen nach Art. 32 DSGVO mit Kriterium und Verantwortlichem |
| [Eckpunkte für eine Betriebsvereinbarung](betriebsvereinbarung-eckpunkte.md) | Punkte, die Arbeitgeber und Betriebsrat regeln sollten |

Zur Lieferung gehören außerdem [Lizenz und Bezug](../betrieb/lizenz-und-bezug.md) und der
[Nachweis mit dem ausgelieferten Modell](../betrieb/modellnachweis.md).

## Unterlage einer Installation

`papaia-ctl privacy-pack --installation --out=<datei> --backup-retention=<tage>` erzeugt beim Betreiber
ein Dokument mit den tatsächlichen Werten der Installation: Auftragsverarbeiter (Modellserver,
Mail-Ausgang), Orte mit Kopien und ihre Fristen und die Verzeichnisse aller eingeschalteten Module.
`papaia-ctl privacy-pack --check` prüft, ob die erzeugten Teile dieser Unterlagen zu den Erklärungen
der Module passen.

## Kriterien

Aussagen wie „technisch gesperrt“ nennen das Abnahmekriterium, das sie belegt (EXK-PLT-65-A4). Welche
Kriterien für eine Version bestanden sind, steht in deren Abnahmebericht.
