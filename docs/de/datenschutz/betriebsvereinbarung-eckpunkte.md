# Eckpunkte für eine Betriebsvereinbarung

Diese Unterlage nennt die Punkte, die Arbeitgeber und Betriebsrat für den Einsatz der Plattform regeln
sollten. Sie ist ein Entwurf der Regelungspunkte, kein Vertragstext. Der Abschluss der Vereinbarung
und die rechtliche Prüfung bleiben Sache des Betreibers. Die Tatsachen zu jedem Punkt stehen in den
verlinkten Unterlagen.

## Regelungspunkte

1. **Zweck.** Die Plattform dient der Unterstützung der Arbeit. Eine Auswertung von Leistung oder
   Verhalten einzelner Beschäftigter findet nicht statt; die Plattform bietet dafür keine Funktion
   ([Begründung](keine-leistungskontrolle.md)).
2. **Module und Funktionen.** Welche Module eingeschaltet sind (Studio, Data, Flow, Assistant, Mein
   Bereich, Anbindungen) und welche Funktionen mit Personenbezug genutzt werden (Gedächtnis der
   Assistenz, Gruppenräume, Erinnerungen). Neue Module werden vor dem Einschalten vorgelegt.
3. **Audit-Prüfung.** Wer die Rolle Audit-Prüfung erhält (Zahl und Funktion der Personen), zu welchen
   Anlässen Ereignisse einer Person mit Namen gelesen werden dürfen und wer die zweite Person ist, die
   bestätigt ([Protokollierung](protokollierung.md#wer-liest)).
4. **Anzeige der Abfragen.** Ob die betroffene Person in „Mein Bereich → Aktivität“ nur Zeit und Rolle
   der Abfrage sieht (Vorgabe) oder mehr; die Plattform zeigt den Namen der prüfenden Person nicht an
   (EXI-PLT-68-A6).
5. **Aufbewahrung.** Frist der Audit-Ereignisse (Vorgabe 12 Monate, einstellbar von 6 bis 36) und die
   Fristen der Module aus den Verzeichnissen der Verarbeitungstätigkeiten; wer eine Frist ändern darf.
6. **Löschsperre.** Anlässe für eine Löschsperre (zum Beispiel ein Rechtsstreit), wer sie setzt und
   aufhebt (zwei Personen) und wie der Betriebsrat davon erfährt.
7. **Nutzungsauswertung.** Nutzungssummen nur je Modul und Zeitraum oder für Gruppen ab 5 Personen;
   wofür sie verwendet werden (Planung von Kapazität und Kosten) und wofür nicht.
8. **Betreiberzugriff.** Wer Root auf dem Host, Zugriff auf Datenbanken oder den Sicherungsschlüssel
   hat; dass diese Zugriffe protokolliert und nur für den Betrieb genutzt werden
   ([Restwege](keine-leistungskontrolle.md#restwege)).
9. **Externe Empfänger.** Ob ein Sprachmodell außerhalb der Installation genutzt wird, ob ein SIEM
   Ereignisse erhält und wer Zugriff auf Kopien außer Haus hat; die Unterlage der Installation
   (`papaia-ctl privacy-pack --installation`) nennt die tatsächlichen Empfänger.
10. **Rechte der Beschäftigten.** Auskunft über die eigenen Daten in „Mein Bereich → Meine Daten“,
    Löschen des Gedächtnisses durch die Person selbst, Export auf Antrag; Ansprechperson für Fragen.
11. **Austritt.** Was mit Konto, Gedächtnis und gemeinsam genutzten Objekten (Abläufe, Apps,
    Definitionen) einer ausscheidenden Person geschieht und an wen diese übergehen.
12. **Änderungen.** Upgrades, die neue Datenarten oder Ereignisse bringen, werden mit der geänderten
    Unterlage vorgelegt; die Unterlagen sind je Version mit dem Kern versioniert.
