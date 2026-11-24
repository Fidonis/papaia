# Sicherung

`papaia-ctl backup` legt verschlüsselte Wiederherstellungspunkte am Sicherungsziel an; wie man
sie einspielt, steht in [Wiederherstellung](../wiederherstellung.md). Dieses Kapitel ergänzt
zwei Fälle, die außerhalb von `papaia-ctl` entstehen: die Sicherung durch den Hypervisor und
Kopien des Sicherungsziels außer Haus.

## Sicherung durch den Hypervisor

Eine VM- oder Volume-Sicherung durch den Hypervisor ist zulässig, aber kein Ersatz für
`papaia-ctl backup`:

- Sie enthält, was `papaia-ctl backup` bewusst auslässt: Vollmachtsschlüssel der Module und
  Rückwegschlüssel eines Upgrades unter `state/rollback/`. Wer die VM-Sicherung hat, kann mit
  diesen Schlüsseln Vollmachten einlösen. Die VM-Sicherung wird deshalb verschlüsselt abgelegt
  und nicht länger aufbewahrt als die Wiederherstellungspunkte (zum Beispiel
  `backup --keep=7` bei täglicher Sicherung: sieben Tage).
- Sie ist kein geprüfter Stand: Datenbanken, die mitten im Schreiben gesichert wurden, starten
  mit Absturzerholung. `papaia-ctl backup` hält dagegen die schreibenden Container für die
  Dauer des Archivs kurz an (`docker pause`), damit keine Datei mitten im Schreiben gesichert wird.

Nach jedem Zurückspielen einer VM- oder Volume-Sicherung, bevor die Personen wieder arbeiten:

1. VM starten. Die Startsperre hält alle Adressen geschlossen, spielt Kontosperren, Löschungen
   und entzogene Rechte des Anmeldedienstes aus dem Löschjournal nach, meldet alle Personen ab
   und öffnet danach selbst (siehe [§S-10](stoerungen.md#s-10-datenstand-älter-als-das-löschjournal)).
2. `papaia-ctl doctor startgate` meldet `pass`; danach zeigt `papaia-ctl doctor` die Prüfung
   `state_epoch` mit `fail` oder `warn`.
3. `papaia-ctl recover-snapshot` übernimmt Einträge, die nur der Spiegel des Löschjournals hat
   (siehe [Kopien außer Haus](#kopien-außer-haus)), löscht alle Rückwegschlüssel unter
   `state/rollback/` aus dem Schnappschuss, setzt im Anmeldedienst „not before“ und entfernt
   die Einwilligungen der Vollmachtshalter (`post-restore`). Jedes Modul wird angehalten und
   erst wieder gestartet, nachdem es sein Löschjournal eingespielt hat (auch Widerrufe von
   Vollmachten). Alte Sitzungen und Vollmachten aus der VM-Sicherung sind danach ungültig.
4. Endet `recover-snapshot` mit Ausgang 3 (ein Modul konnte nicht einspielen, oder
   Löschjournal oder Spiegel sind nicht erreichbar), die Ursache beheben und
   `papaia-ctl recover-snapshot` erneut aufrufen; es wiederholt nur die offenen Schritte.
5. `papaia-ctl doctor` endet mit Ausgang 0; `state_epoch` meldet `pass`.
6. Den Personen den Mustertext unten senden.

Die Schritte beschreibt auch
[Wiederherstellung](../wiederherstellung.md#nach-dem-zurückspielen-recover-snapshot).

Mustertext zur Neuerteilung der Vollmachten:

> Betreff: Bitte Vollmachten neu erteilen
>
> Die Plattform wurde am <Datum> auf einen früheren Stand zurückgesetzt. Aus Sicherheitsgründen
> sind dabei alle Anmeldungen und alle Vollmachten, die Sie Flow oder Assistant erteilt hatten,
> beendet worden. Bitte melden Sie sich neu an und erteilen Sie in Mein Bereich die Vollmachten
> neu, die Sie weiter nutzen wollen. Abläufe, die eine Vollmacht brauchen, warten bis dahin.
> Fragen an: <Ansprechstelle>

## Kopien außer Haus

Eine Kopie des Sicherungsziels außer Haus (Regel 3-2-1: drei Kopien, zwei Medien, eine außer
Haus; siehe BSI IT-Grundschutz, Baustein CON.3 Datensicherungskonzept,
<https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html>)
ist Sache des Betriebs. Sie trägt ein Löschjournal, das mit dem Tag der Kopie endet. Deshalb
wird das Löschjournal zusätzlich an eine zweite Ablage gespiegelt, am besten Speicher außer
Haus, der nur Anhängen erlaubt:

```sh
papaia-ctl backup mirror --erasure-mirror=/mnt/offsite/papaia-loeschjournal \
  --offsite-retention=180
```

`--offsite-retention` ist die längste Aufbewahrung einer Kopie außer Haus in Tagen. Jedes
`backup` hängt an den Spiegel an; ist er nicht erreichbar, endet die Sicherung mit `partial`.
`restore` und `recover-snapshot` spielen die Vereinigung von Ziel und Spiegel ein. Einzelheiten
stehen in [Wiederherstellung](../wiederherstellung.md#kopien-außer-haus).

Ohne Spiegel gibt `restore` diesen Satz aus, und er gilt:

„Wird von einer Kopie außer Haus wiederhergestellt, kehren Löschungen nach dem Tag dieser
Kopie zurück. Führen Sie danach für jede Person aus der Liste der Löschnachweise seit diesem
Tag `person erase` erneut aus.“

Die Liste der Löschnachweise führt der Betrieb deshalb außerhalb der Installation: Jeder
Nachweis aus Schritt 6 der [Betroffenenanfrage](auskunft-und-loeschung.md#ablauf-in-sechs-schritten)
kommt mit Datum und Kennung der Person in diese Liste. Die Liste enthält keine Inhalte.
