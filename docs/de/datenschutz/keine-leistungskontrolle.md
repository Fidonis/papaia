# Warum die Plattform keine Leistungs- oder Verhaltenskontrolle anbietet

Diese Unterlage ist für den Betriebsrat und den Arbeitgeber geschrieben. Sie begründet, warum die
Plattform keine Auswertung über einzelne Personen anbietet, und nennt die Wege, auf denen Daten trotzdem
technisch lesbar sind. Jeder Grund nennt das Abnahmekriterium, das ihn belegt; welche Kriterien
bestanden sind, steht im Abnahmebericht der Version.

## Satz für die Betriebsvereinbarung

Wörtlich, zur Übernahme:

„Die Software bietet keine Funktion, mit der Leistung oder Verhalten einzelner Beschäftigter
ausgewertet werden kann. Personen mit Zugriff auf den Server oder die Datenbanken können
Protokolldaten jedoch technisch lesen. Ob die Software zur Überwachung geeignet ist im Sinne des § 87
Abs. 1 Nr. 6 BetrVG, beurteilen Arbeitgeber und Betriebsrat; diese Unterlage liefert dafür die
Tatsachen.“

Quelle der Vorschrift: <https://www.gesetze-im-internet.de/betrvg/__87.html>.

## Gründe

1. Das Audit enthält keine Inhalte der Arbeit: keine Titel, Suchtexte, Eingaben oder Antworten
   (PLT-19-A4).
2. Audit-Ereignisse liest nur, wer die Rolle Audit-Prüfung hat. Namen sieht diese Person nur mit
   Begründung und Bestätigung durch eine zweite Person, und die betroffene Person sieht jede solche
   Abfrage in „Mein Bereich“ (PLT-64-A1, PLT-64-A2, EXI-PLT-68-A6).
3. Die Lese-Schnittstelle des Audits bietet kein Gruppieren und kein Zählen nach Person an; eine
   solche Anfrage wird abgewiesen (GV-03).
4. Messwerte tragen keine Personenkennung, keinen Benutzernamen und keine Mailadresse; die erlaubten
   Etiketten sind festgelegt und werden von `papaia-ctl doctor` geprüft (EXI-PLT-68-A2).
5. Nutzungssummen gibt es nur je Modul und Zeitraum oder für Gruppen ab 5 Personen. Werte je Person
   sieht nur die Rolle Audit-Prüfung mit Begründung, und die Abfrage ist ein Audit-Ereignis (GV-28,
   EXI-PLT-68-A3).
6. Das Modell-Gateway speichert keine Eingaben und keine Antworten des Modells; geprüft wird das mit
   einem Markierungswort, das nach Anfragen aus allen Modulen in keinem Protokoll und keiner Datenbank
   außerhalb des Verlaufs des Moduls auftaucht (EXI-PLT-68-A4).
7. Verwaltungsoberflächen zeigen Kennungen statt Namen, wo eine Person nicht selbst handelt (PLT-64).

Eine Funktion, die Arbeitsmenge, Arbeitszeiten oder Fehler einer einzelnen Person zusammenstellt, ist
nicht Teil der Plattform. Wer sie nachrüsten will, braucht eine Änderung am Code; jede Änderung der
Lieferung ist im Änderungsprotokoll der Version sichtbar.

## Restwege

Die folgenden Personen können Daten technisch lesen, weil sie den Betrieb verantworten. Die Plattform
kann diese Wege nicht schließen, ohne den Betrieb unmöglich zu machen; sie müssen organisatorisch
geregelt werden (Betriebsvereinbarung, [Eckpunkte](betriebsvereinbarung-eckpunkte.md)).

| Pfad | Was lesbar ist | Klartext oder verschlüsselt | Organisatorische Maßnahme |
|---|---|---|---|
| Root auf dem Host | alle Volumes, Datenbanken, Protokolle und die Schlüssel im Konfigurationsverzeichnis | Klartext in den Volumes | wenige benannte Personen; Protokoll der Host-Zugriffe beim Betreiber; Regel in der Betriebsvereinbarung |
| Zugriff auf den Docker-Socket | mit dem Vermittler `papaia-docker-gate` nur Status sowie Start und Stopp der Container der Installation ([Vermittler](../../docker-gate.md)); ohne Vermittler (nicht unterstützt) dasselbe wie Root | wie Root | Manager nur mit Vermittler betreiben; Socket nur für Root |
| Eigentümer von `papaia-audit-db` und der Moduldatenbanken | Audit-Ereignisse mit der Kennung `sub` im Klartext; Daten der Module | Klartext in der Datenbank | Kennwort des Eigentümers nur für Einrichtung und Upgrade; Eingriffe in das Audit werden über die Hash-Kette erkannt |
| Verwaltung des Proxys (Nginx Proxy Manager) | Zugriffsprotokolle mit Adresse, Zeit und Pfad | Klartext | Verwaltungsoberfläche nur aus dem Verwaltungsnetz; wenige benannte Personen |
| Verwaltung des Modell-Gateways | Nutzungszähler je Modulschlüssel, keine Inhalte | Klartext | Hauptschlüssel bleibt im Container; Zugang nur für den Betrieb |
| Konto des Lebenszyklus-Dienstes mit `manage-users` | Konten, Sitzungen und Rollen im Anmeldedienst | Klartext im Anmeldedienst | Dienstkonto ohne Anmeldung durch Personen; Schlüssel nur im Dienst |
| Inhaber des Sicherungsschlüssels | alles, was die Sicherung enthält | am Sicherungsziel verschlüsselt, nach Entschlüsselung Klartext | zwei benannte Empfänger; Schlüssel getrennt vom Sicherungsziel verwahrt |
| Betreiber eines SIEM | die ausgeleiteten Audit-Ereignisse | verschlüsselt übertragen, Speicherung nach den Regeln des SIEM | Frist und Zugriff im SIEM regelt der Betreiber |
| Ausführende und Bestätigende eines Personenexports | das Archiv der Daten einer Person | mit Passphrase verschlüsselt | zwei Personen; Weitergabe nur an die betroffene Person |
