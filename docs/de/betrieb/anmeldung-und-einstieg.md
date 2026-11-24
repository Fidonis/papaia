# Anmeldung, Abmeldung und Einstiegsseite

Dieses Dokument beschreibt für den Betrieb, wie sich Personen in allen Modulen gleich
anmelden und abmelden und auf welcher Seite sie nach der Anmeldung landen. Die technischen
Einzelheiten stehen im [Keycloak-README](../../../src/infra/keycloak/README.md).

## Einstiegsseite

Die Einstiegsseite der Installation ist die **Übersicht von Mein Bereich**,
`https://me.<domain>/` (Profil `me`, Variable `ME_PUBLIC_URL`). Wer die Hauptadresse der
Installation ohne Modul-Hostnamen öffnet, also `https://<domain>/`, wird dorthin
weitergeleitet und nach der Anmeldung dort begrüßt. Alle Personen landen auf derselben
Seite; sie zeigt je Modul, das die Person sehen darf, eine Kachel aus dem Plattformkatalog.

- **Mitgelieferter Proxy** (`REVERSE_PROXY_PROVIDER=internal_nginx`): `papaia-ctl start`
  legt den Proxy-Host der Hauptadresse an, der mit `302` auf die Einstiegsseite leitet. Ein
  Zertifikat oder HSTS, das der Betrieb dort einträgt, bleibt erhalten.
- **Eigener Proxy** (`external_proxy`): `papaia-ctl proxy list` nennt die Zeile
  `<domain>  redirect 302 https://me.<domain>/`. Diese Weiterleitung richtet der Betrieb am
  eigenen Proxy ein.
- **Ohne Mein Bereich** (Profil `me` aus) gibt es keine Einstiegsseite: Jedes Modul zeigt
  nach der Anmeldung seine eigene Startseite `/`. Einen Proxy-Host der Hauptadresse, den
  `papaia-ctl start` angelegt hat, entfernt der nächste Start.
- **Hauptadresse schon belegt:** Bedient ein anderes Modul die Hauptadresse (etwa Chat mit
  `DOMAIN_SERVER=https://<domain>`), gibt es keine Weiterleitung; `papaia-ctl start` und
  `papaia-ctl proxy list` nennen das in einem Hinweis. Einen Proxy-Host an der Hauptadresse,
  der nicht auf Mein Bereich zeigt, lässt `papaia-ctl start` unverändert.

## Anmeldung

Alle Module melden über denselben Anmeldedienst (Keycloak, Realm `papaia`) an. Die
Anmeldeseite trägt das Erscheinungsbild `papaia` aus den Werten des Kits und folgt der
Systemeinstellung hell oder dunkel. `papaia-ctl realm sync` weist es dem Anmelde-Client
jedes Moduls zu, sofern dort kein anderes eingetragen ist.

## Abmeldung

Wer sich in einem Modul abmeldet, beendet die gemeinsame Sitzung am Anmeldedienst. Der
Anmeldedienst ruft danach die Abmeldeadresse (Back-Channel-Logout) jedes anderen Moduls auf,
und das Modul beendet seine Sitzungen sofort. `papaia-ctl realm sync` trägt diese Adressen
an den Anmelde-Clients von Mein Bereich, Flow, Studio und Assistant ein. Data hat keine
solche Adresse; seine Sitzung endet mit der nächsten fehlgeschlagenen Erneuerung, spätestens
nach 240 Sekunden. Spätestens 300 Sekunden nach der Abmeldung liefert kein Modul mehr Daten,
und jedes leitet zur Anmeldung.

Nach der Abmeldung zeigt das Modul die Seite „Abgemeldet“ aus dem Kit mit dem Satz „Sie sind
abgemeldet. Schließen Sie das Browserfenster, wenn andere diesen Rechner nutzen.“ und einem
Verweis „Erneut anmelden“.

Der Anmeldedienst ruft die Abmeldeadressen der Erweiterungen aus seinem Container über
deren öffentliche Namen auf. Lokal (`*.papaia.localhost`) erreicht er sie dort nicht, und
auch an einer Serverdomäne kann der Aufruf scheitern, wenn der Server seine eigene
öffentliche Adresse von innen nicht erreicht. Dann gilt die Rückfallebene: Das Modul merkt
die Abmeldung bei der nächsten Erneuerung, spätestens nach 240 Sekunden, sofern seine
Sitzung von dieser Erneuerung abhängt. `papaia-ctl realm sync` nennt lokal die betroffenen
Clients in einem Hinweis.

Ohne Proxy (`no_proxy`) trägt der Abgleich die Abmeldeadressen der Erweiterungen nicht ein;
der Betrieb setzt sie dann in der Verwaltungsoberfläche von Keycloak am jeweiligen Client.
