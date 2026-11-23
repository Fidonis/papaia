# Verzeichnis der Verarbeitungstätigkeiten: Kern

<!-- generiert: privacy-pack, nicht von Hand ändern -->
### Verbindungen (connections, core:connections)

Aufbewahrung insgesamt: bis die Person die Daten löscht

| Datenkategorie | Betroffene Personen | Zweck | Ort (Dienst, Volume) | Aufbewahrung | Empfänger | Löschweg | Zugriffsweg der Person | Rechtsgrundlage | Datenklasse | Klartext/verschlüsselt |
|---|---|---|---|---|---|---|---|---|---|---|
| Konten | angemeldete Personen | Konten einer Person oder Gruppe auf freigegebenen Zielen mit Benutzername und verschlüsselten Zugangsdaten. | Dienst connections; Volume connections-db (in der Sicherung); Volume connections-keys (in der Sicherung) | bis die Person die Daten löscht | intern: Kern; extern: nur nach der Liste der Auftragsverarbeiter der Installation | durch die Person in Mein Bereich | Mein Bereich (Meine Daten) | Vorschlag des Moduls: Art. 6 Abs. 1 lit. f DSGVO; vom Verantwortlichen zu prüfen | vertraulich | Klartext im Volume (keine Verschlüsselung deklariert) |
| Journal der Nutzungen | angemeldete Personen | Unveränderlicher Nachweis, wer wann ein Ziel eingerichtet, ein Konto angelegt oder genutzt hat. Ohne Zugangsdaten. | Dienst connections; Volume connections-db (in der Sicherung); Volume connections-keys (in der Sicherung) | nach der gesetzlichen Aufbewahrungspflicht (Einträge sind verkettet und werden nicht einzeln entfernt.) | intern: Kern; extern: nur nach der Liste der Auftragsverarbeiter der Installation | auf Antrag: Anfrage an den Betreiber der Installation, der die Aufbewahrungspflicht prüft. Zuständig: Betreiber der Installation | Auskunft auf Antrag beim Verantwortlichen | Vorschlag des Moduls: Art. 6 Abs. 1 lit. f DSGVO; vom Verantwortlichen zu prüfen | personenbezogen | Klartext im Volume (keine Verschlüsselung deklariert) |

Ohne Angabe zur Speicherung (das Modul muss storage deklarieren):

- qdrant.collections (core:rag)
<!-- ende generiert -->
