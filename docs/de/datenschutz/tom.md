# Technische und organisatorische Maßnahmen

Gliederung nach Art. 32 DSGVO. Jede Maßnahme nennt das Abnahmekriterium, das sie belegt, und den Ort
der Beschreibung. Maßnahmen, die nur der Betreiber treffen kann, sind in der Spalte „Verantwortlich“
als „Betreiber“ markiert; die übrigen leistet die Plattform. Welche Kriterien bestanden sind, steht im
Abnahmebericht der Version.

## Vertraulichkeit

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| Anmeldung beim Anmeldedienst der Installation mit zweitem Faktor; gehärteter Realm ohne Kennwort-Grant | PLT-21 | [Konfiguration](../../configuration.md) | Plattform |
| Rechteprüfung bei jedem Zugriff im Modul, nicht in der Oberfläche | PLT-50 | Dokumentation des Moduls | Plattform |
| Genau eine Audience je Token; jedes Modul nimmt nur Token für sich an | PLT-12 | [Architektur](../../architecture.md) | Plattform |
| Ausgang nur über `papaia-egress` an freigegebene Ziele | OPS-07 | [Der einzige Ausgang](../../egress.md) | Plattform |
| Docker-Socket für den Manager nur über den Vermittler `papaia-docker-gate` | EXI-S07 | [Vermittler](../../docker-gate.md) | Plattform |
| Kleiner Kreis von Personen mit Root, Datenbank- und Sicherungszugriff; Protokoll der Host-Zugriffe | keines (organisatorische Maßnahme des Betreibers); die Plattform legt die Wege offen (EXK-PLT-65-A5) | [Restwege](keine-leistungskontrolle.md#restwege) | Betreiber |
| Verwaltungsoberflächen nur aus dem Verwaltungsnetz erreichbar | EXI-PLT-65-A7 | Betriebshandbuch | Betreiber |

## Integrität

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| Audit-Ereignisse aller Quellen in einem Speicher, nur anfügen, Hash-Kette je Quelle | PLT-19 | [Der Audit-Speicher](../../audit.md) | Plattform |
| Stündlich signierte Kettenköpfe am Sicherungsziel; Prüfung nennt das erste nicht passende Ereignis | ISB-PLT-19-A6, EXI-PLT-19-A9 | [Der Audit-Speicher](../../audit.md#verification-and-signed-heads) | Plattform |
| Images mit Digest festgeschrieben und signiert; Prüfung vor jedem Start | PLT-36, PLT-37 | [Lizenz und Bezug](../betrieb/lizenz-und-bezug.md#3-bezug-der-images) | Plattform |
| Eingaben an jeder Schnittstelle gegen ein Schema geprüft, unbekannte Felder abgewiesen | PLT-50 | Dokumentation des Moduls | Plattform |

## Verfügbarkeit

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| Verschlüsselte Sicherung aller Volumes mit Personendaten an ein Ziel außerhalb des Hosts | PLT-35 | [Sicherung](../../../README.md#backup) | Plattform |
| Sicherungsziel auf getrenntem Speicher; Kopie außer Haus mit eigener Frist | PLT-35 | Betriebshandbuch | Betreiber |
| Gesundheitsprüfung aller Dienste mit `papaia-ctl doctor` | EXK-PLT-68-A3 | [Fehlersuche](../../troubleshooting.md) | Plattform |

## Belastbarkeit

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| Module laufen weiter, wenn der Audit-Speicher nicht erreichbar ist; Ereignisse warten in der Ausgangswarteschlange | ISB-PLT-19-A8, EXI-PLT-19-A8 | [Der Audit-Speicher](../../audit.md#ingest) | Plattform |
| Protokolle mit Größenbegrenzung und Rotation | EXK-PLT-68-A1 | Betriebshandbuch | Plattform |
| Not-Halt aller schreibenden, sendenden und löschenden Wirkungen mit einem Befehl | PLT-61 | [Not-Halt](../../halt.md) | Plattform |
| Host nach der Mindestausstattung bemessen | OPS-14 | [Modellnachweis](../betrieb/modellnachweis.md) | Betreiber |

## Wiederherstellung

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| Wiederherstellung auf einem zweiten Host nach Anleitung | PLT-35 | Betriebshandbuch | Plattform |
| Löschungen und Kontosperren bleiben nach einer Wiederherstellung wirksam (Löschjournal am Sicherungsziel) | PLT-66 | [Kontolebenszyklus](../../lifecycle.md#the-erasure-journal-identity) | Plattform |
| Wiederherstellung regelmäßig üben | PLT-35 | Betriebshandbuch | Betreiber |

## Überprüfung

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| Abnahmebericht je Version mit allen Kriterien dieser Unterlage | PLT-70 | Lieferunterlagen | Plattform |
| Verzeichnis der Verarbeitungstätigkeiten wird aus den Erklärungen der Module erzeugt und im CI auf Gleichlauf geprüft | EXK-PLT-65-A2 | [Verzeichnis Kern](vvt/kern.md) | Plattform |
| Schwachstellen-Scan der eigenen Images beim Build bei jeder Änderung und täglich (erneuter Scan des Stands des Standardzweigs); Schwachstellen-Scan der Fremd-Images wöchentlich und bei jeder Änderung unter `src/` | EXK-PLT-71-A4 | [Lizenz und Bezug](../betrieb/lizenz-und-bezug.md#5-unterstützung-und-sicherheitskorrekturen) | Plattform |
| Regelmäßige Durchsicht der Rollen und der Audit-Abfragen | PLT-64 | [Protokollierung](protokollierung.md) | Betreiber |

## Pseudonymisierung

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| Audit zeigt Personen als Pseudonym; Namen nur mit Begründung und zweiter Person | PLT-64-A1, PLT-64-A2 | [Protokollierung](protokollierung.md#wer-liest) | Plattform |
| Löschjournal führt statt der Kennung einen HMAC-Wert | PLT-66 | [Kontolebenszyklus](../../lifecycle.md#the-erasure-journal-identity) | Plattform |
| Messwerte ohne Personenkennung; Summen erst ab 5 Personen | EXI-PLT-68-A2, EXI-PLT-68-A3 | [Protokollierung](protokollierung.md#messwerte) | Plattform |

## Verschlüsselung

| Maßnahme | Kriterium | Ort | Verantwortlich |
|---|---|---|---|
| TLS auf allen internen Wegen mit der internen Zertifizierungsstelle; Zertifikate des Audit-Eingangs je Quelle | PLT-23 | [Der Audit-Speicher](../../audit.md#certificates-of-the-sources) | Plattform |
| TLS an allen öffentlichen Hostnamen mit Zertifikaten des Betreibers | EXI-PLT-65-A2 | Betriebshandbuch | Betreiber |
| Sicherungen mit age an zwei Empfänger verschlüsselt | PLT-35 | [Sicherungsschlüssel](../../../README.md#backup-keys-and-target) | Plattform |
| Verschlüsselung der Datenträger des Hosts | keines (organisatorische Maßnahme des Betreibers) | Betriebshandbuch | Betreiber |
