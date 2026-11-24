# Studio-Apps und der Rand des Stapels

Dieses Dokument beschreibt für den Betrieb, was der Rand (der mitgelieferte Proxy) für die
App-Hosts von Studio tut, wie man es prüft und was bei einem Fund zu tun ist. Die englische
Beschreibung steht im README unter „Studio app hosts at the edge“.

## Worum es geht

Studio liefert Apps über den App-Host aus. Mit einer zweiten Domain (`INGRESS_APP_DOMAIN`)
liegt er auf einer eigenen Site; das ist empfohlen. Ohne zweite Domain liegt er auf
`apps.<Domain>` und dessen Unterhosts. Dann teilen sich Apps und Plattform die Site, und der
Browser schickt die Cookies der Plattform auch bei Anfragen mit, die eine App auslöst.
`SameSite` trennt die beiden dann nicht mehr.

## Was der Rand tut

- Jeder Proxy-Host lehnt eine schreibende Anfrage (alles außer `GET`, `HEAD`, `OPTIONS`) ab,
  deren `Origin` ein App-Host ist: `apps.<Domain>`, die zweite Domain oder ein Host darunter.
  Antwort `403` mit `X-Papaia-Error: app_origin_refused`. Das gilt in beiden Betriebsarten
  und auch für Proxy-Hosts, die von Hand angelegt wurden.
- Jede Ablehnung ergibt eine Zeile im Format `papaia.audit/1` in
  `$PAPAIA_CONFIG_DIR/infra/nginx/nginx-data/logs/papaia-audit.log` (Ereignis
  `protected_host_denied`, Schreiber `papaia-edge`). Die Zeile nennt den geschützten Host
  und die Korrelationskennung, nie eine Person, einen Ursprung, einen Pfad oder Inhalte.
- `papaia-ctl start` richtet die Regel über `npm-provision` ein. Lehnt der Proxy die
  Konfiguration ab, bleibt die vorige stehen und `npm-provision` endet mit Fehler.

## Prüfen

```sh
tools/papaia-ctl doctor edge_app_origin
```

- `pass`: die Regel ist aktiv, und kein Cookie der Plattform hat ein `Domain`-Attribut, das
  App-Hosts einschließt. Die Zahl abgelehnter Anfragen steht in der Zusammenfassung.
- `fail` mit „does not refuse writes from the app hosts“: `tools/papaia-ctl npm-provision`
  ausführen.
- `fail` mit „platform cookies with a Domain“: Der genannte Dienst setzt ein Cookie für die
  ganze Domain. Die Einstellung dieses Dienstes so ändern, dass er Cookies nur für seinen
  eigenen Host setzt; bis dahin eine zweite Domain für die Apps einrichten.
- `warn`: Ein Host war nicht lesbar, der Proxy läuft nicht, oder ein externer Proxy wird
  verwendet. Ein externer Proxy muss dieselbe Ablehnung selbst umsetzen.

## Abhilfe für das Restrisiko

Die Maßnahmen ersetzen die getrennte Site nicht. Dauerhafte Abhilfe ist eine zweite
registrierbare Domain für die Apps (`INGRESS_APP_DOMAIN`), danach `papaia-ctl start`.
