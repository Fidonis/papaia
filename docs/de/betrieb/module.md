# Module

Der Kern trägt Anmeldung, Chat, Modell-Gateway, Manager, Mein Bereich, Audit-Log und Rand.
Die Module Studio, Data, Flow, Assistant und Paperless kommen als Add-ons dazu, jedes mit
eigenem Compose-Projekt, eigener Datenbank und eigenem Netz. Welches Modul ein anderes
braucht, steht im Manifest jedes Moduls (`papaia-app.yaml`, Feld `requires.addons`); die
Matrix unten gibt diese Angaben wieder.

## Abhängigkeitsmatrix

Lesart: Die Zeile braucht die Spalte. „nötig“ heißt, das Modul startet nicht ohne die Spalte;
„erweitert um …“ heißt, das Modul läuft auch ohne die Spalte und bietet mit ihr die genannte
Funktion zusätzlich; „unabhängig“ heißt, keines der beiden sieht das andere.

| braucht ↓ / von → | Kern | Studio | Data | Flow | Assistant | Paperless |
|---|---|---|---|---|---|---|
| Kern | – | unabhängig | unabhängig | unabhängig | unabhängig | unabhängig |
| Studio | nötig | – | erweitert um die Übergabe von Apps an Data | unabhängig | unabhängig | unabhängig |
| Data | nötig | unabhängig | – | unabhängig | unabhängig | unabhängig |
| Flow | nötig | unabhängig | unabhängig | – | unabhängig | unabhängig |
| Assistant | nötig | unabhängig | unabhängig | erweitert um das Starten von Abläufen in Flow | – | unabhängig |
| Paperless | nötig | unabhängig | unabhängig | unabhängig | unabhängig | – |

- Jedes Modul braucht den Kern in der Version seiner Suite (`requires.addon_api`);
  `papaia-ctl addon check` prüft das vor jeder Installation.
- Mein Bereich und das Verbindungsregister sind Profile des Kerns (`me`, `connections`), keine
  Module. Mein Bereich startet vor jedem Modul.
- Es gibt keinen Kreis aus „nötig“: Jedes Modul lässt sich allein mit dem Kern betreiben.

## Mein Bereich und das Verbindungsregister

Sind beide Profile an (`me` und `connections`), zeigt Mein Bereich einer Person ihre Konten,
Vollmachten und Nutzungen im Verbindungsregister, und sie kann dort eine Vollmacht beenden.
Dafür erhält `me-web` ein Client-Zertifikat der Plattform-PKI, tritt dem Netz des Registers
bei, und das Register nimmt `papaia-me` als Personen-Client an. Ein selbst gesetzter Wert von
`CONNECTIONS_PERSON_CLIENTS` bleibt erhalten. Ist eines der beiden Profile aus, entfällt all das.

Das Tauschrecht kommt aus der Kopplung `papaia-me` -> `papaia-connections` der Stückliste,
Wirkungen `r` (lesen) und `d` (Vollmacht beenden). Weil sie löscht, braucht sie nach der
Bestätigung die Freigabe durch ein zweites Konto des Hosts:

```sh
papaia-ctl pairing list
papaia-ctl pairing confirm --approve-pairings=<sha256>
# als zweites Konto des Hosts, nicht dasselbe wie oben, mit sudo:
sudo papaia-ctl pairing approve --client=papaia-me --audience=papaia-connections --effects=rd
# wieder als Eigentümer des Konfigurationsverzeichnisses:
papaia-ctl start
```

Die zweite Freigabe läuft mit `sudo`, weil `security/pairings.yaml` dem Konto gehört, dem das
Konfigurationsverzeichnis gehört. Das zweite Konto braucht dafür eine sudoers-Regel für genau
`tools/papaia-ctl` dieses Checkouts. Als root vertrauen die Befehle `pairing` der Datei und dem
Ordner `security/` auch dann, wenn sie dem Eigentümer des Konfigurationsverzeichnisses gehören;
das Verzeichnis selbst darf kein symbolischer Link und für Gruppe und andere nicht beschreibbar
sein. Eine Datei oder ein Ordner eines dritten Kontos, eine für Gruppe oder andere beschreibbare
Datei und ein symbolischer Link werden abgelehnt. root liest und schreibt nur über die geöffneten
Verzeichnisse und übergibt alles, was es anlegt (neue `pairings.yaml`, Sperrdatei, Audit-Ausgang),
dem Eigentümer des Konfigurationsverzeichnisses; danach gehört dort nichts root, und `start` des
Eigentümers liest die Datei. Die Audit-Zeile der Freigabe nennt das zweite Konto.

Was die zweite Freigabe leistet und was nicht: Sie ist eine organisatorische Kontrolle mit
Nachweis (die Zeile `pairing.approve` des zweiten Kontos), kein Schutz gegen das Konto, dem das
Konfigurationsverzeichnis gehört. Dieses Konto hat die Admin-Zugangsdaten des Anmeldedienstes
(`infra/keycloak/.env`) und darf `pairings.yaml` von Hand ändern; es kann ein Tauschrecht also
auch ohne zweite Person vergeben.

Vor der Freigabe zeigt Mein Bereich keine Daten des Registers. Die Kopplung hat genau die
Wirkungen `r` und `d`; mehr oder weniger lehnt der Kern ab, die Freigabe durch ein zweites Konto
ist also immer nötig. Mein Bereich ruft nur die Routen auf, die Konten, Mandate und Nutzungen
auflisten, und die eine, die ein Mandat beendet. Das Register selbst beschränkt einen
Personen-Client noch nicht auf diese Aufrufe: Es nimmt ein Token von `papaia-me` wie das der
Person selbst an. Eine Beschränkung der Aufrufe je Client im Register steht noch aus.

Ein Stapel aus Kern, Manager, Mein Bereich und Assistant ohne Flow, Studio und Data ist
vollständig: Assistant läuft ohne Flow und bietet dann nur das Starten von Abläufen nicht an.

## Module nachrüsten

Ein Modul lässt sich jederzeit mit zwei Befehlen nachrüsten; die vorhandenen Module und ihre
Daten bleiben unverändert:

```sh
papaia-ctl addon install papaia-flow --path=/opt/papaia-flow/deploy/papaia-addon
papaia-ctl addon start papaia-flow
papaia-ctl doctor
```

- `<modul>` in den Befehlen `addon install`, `start`, `stop`, `remove`, `uninstall` und
  `upgrade` von `papaia-ctl` ist der Manifestname des Moduls (`name` in `papaia-app.yaml`): `papaia-studio`
  (Studio), `papaia-data` (Data), `papaia-flow` (Flow), `papaia-assist` (Assistant) und
  `paperless` (Paperless). `addon install` trägt das Modul unter dem angegebenen Namen ein;
  `addon upgrade`, die Reihenfolge beim Start und die Hinweise beim Entfernen gelten nur, wenn
  dieser Name der Manifestname ist.
- `addon install` prüft vor jeder Änderung die Verträglichkeit mit dem Kern und der Suite und
  die Images gegen die signierte Stückliste.
- Sind zwei Module mit „erweitert um …“ beide vorhanden, startet und hebt der Kern sie in der
  Reihenfolge der Matrix: Data vor Studio, Flow vor Assistant.
- `papaia-ctl pairing list` zeigt danach die Kopplungen, die das neue Modul mitbringt;
  `papaia-ctl pairing confirm --approve-pairings=<sha256>` gibt sie frei; den Prüfwert nennt
  `pairing list`.

## Werkzeug-Server außerhalb der Suite im Chat

Ein Werkzeug-Server, der nicht zur Suite gehört (`trust: addon` im Katalog), erreicht den
Chat nur über das Chat-Relais `papaia-chat-relay` (Profil `librechat`). Der Server bekommt
nie das Token des Chats, sondern ein Token, das nur für ihn gilt. Einzelheiten:
[docs/chat-relay.md](../../chat-relay.md).

- Ohne freigegebenen Server lehnt das Relais jeden Aufruf ab. Freigegeben ist ein Server,
  wenn er in `$PAPAIA_CONFIG_DIR/chat-relay/servers.json` steht und die Kopplung
  `papaia-chat-relay` → `<audience>` in `security/pairings.yaml` bestätigt ist.
- Freigeben, zurücknehmen und anzeigen:

  ```sh
  papaia-ctl addon chat allow  <add-on>
  papaia-ctl addon chat revoke <add-on>
  papaia-ctl addon chat list
  ```

  `allow` zeigt das Add-on, seine Audience, seine Werkzeuge mit Wirkung und die höchste
  Datenklasse und fragt dann. Ohne Terminal nennt `--approve=<audience>` die angezeigte
  Audience; `-y` wird abgelehnt. Freigegeben werden kann nur ein installiertes Add-on
  außerhalb der Suite mit genau einem Werkzeug-Server für Personen, mindestens einem
  Werkzeug und einem eigenen App-Netz (`networks.app_network`), dem nur das Relais
  beitritt (erzeugte Datei `overrides/docker-compose.chat-relay-<add-on>.override.yml`).
  Abgelehnt werden Module der Suite (sie brauchen keine Freigabe), unbekannte
  Namen, Add-ons, die `librechat` an eines ihrer Netze hängen, und Audiences, die selbst
  Tokens tauschen.
- Schreibt, sendet oder löscht ein Werkzeug, oder gilt das Vier-Augen-Prinzip
  (`approvals.four_eyes`, im Profil `kritis` immer), wartet die Freigabe auf ein zweites
  Host-Konto, das denselben Befehl ausführt. Dasselbe Konto wird abgelehnt.
  Die Befehle zur Freigabe von Kopplungen (`pairing`) lehnen den Client
  `papaia-chat-relay` ab; die Freigabe hat nur diesen einen Weg.
- Eine bestätigte Freigabe eines laufenden Add-ons schreibt `servers.json` und erzeugt im
  Chat einen Eintrag mit dem Namen der Audience, der auf das Relais zeigt
  (`http://papaia-chat-relay:8080/servers/<audience>/mcp`), nie auf das Add-on. Der
  Katalog-Eintrag behält `trust: addon`; die Audience des Add-ons kommt nicht in das Token
  des Chats. Erst `papaia-ctl start` gibt dem Relais den Scope und lädt den Eintrag in
  LibreChat.
- `addon chat revoke`, `addon uninstall` und `addon stop` nehmen das Add-on sofort von der
  Liste; ab dann lehnt das Relais es ab. Eintrag im Chat und Scope des Relais entfallen beim
  nächsten `papaia-ctl start`. Deklariert das Add-on nach einem Upgrade andere Wirkungen
  (etwa ein neues schreibendes Werkzeug), bleibt es draußen, bis es zurückgenommen und neu
  freigegeben ist; `addon chat list` nennt den Grund.
- Jede Entscheidung und jede Ablehnung ist eine Zeile `papaia.audit/1` im Audit-Ausgang des
  Kerns (`chat_relay.allow`, `chat_relay.approve`, `chat_relay.revoke`) mit Host-Konto,
  Add-on, Katalog-Eintrag und Datenklasse; jedes Schreiben der Liste ist eine Zeile
  `chat_relay.list_write`.
- `papaia-ctl realm sync` legt dann den Client `papaia-chat-relay` im Realm an, gibt ihm
  genau die bestätigten Scopes `aud-<audience>` und löscht ihn wieder, wenn keine Freigabe
  mehr besteht. Den Schlüssel des Clients erzeugt `papaia-ctl start` unter
  `security/chat-relay/` (nur für den Eigentümer lesbar).
- Eine Kopplung des Relais mit einem Server der Suite, einem Kerndienst oder einem Add-on,
  das den Chat an eines seiner Netze hängt, bricht den Realm-Abgleich vor jeder Änderung ab.
- Jeder Aufruf mit geprüfter Identität steht als Zeile `papaia.audit/1` im Log des
  Containers (`docker compose logs papaia-chat-relay`): Person, Add-on, Werkzeug, Ergebnis,
  Fehlercode und Korrelations-ID, nie ein Token, die Argumente oder das Ergebnis.
- Grenzen: 1 MiB je Anfrage, 8 MiB je Antwort, 60 s je Aufruf (auch wenn das Add-on langsam
  sendet), 60 Aufrufe je Minute je Person und Add-on, höchstens 128 Anfragen gleichzeitig
  (sonst 503 `busy`). Fehlercodes und ihre Ursachen stehen in der Tabelle „Operation“ von
  docs/chat-relay.md.

## Module entfernen

```sh
papaia-ctl addon remove <modul>        # abschalten; Einstellungen und Daten bleiben
papaia-ctl addon uninstall <modul>     # Container, Netze, Einstellungen, Proxy-Hosts und Anmeldeclients weg;
                                       # die Volumes nur mit --purge-data
```

Braucht ein anderes aktives Modul das zu entfernende („nötig“), lehnen beide Befehle ab, bevor
sie etwas ändern, und nennen das abhängige Modul:

```
ERROR: addon '<modul>' is required by '<abhängiges modul>'. Remove those first, or pass --force.
```

In dieser Suite braucht kein Modul ein anderes Modul mit „nötig“; die Ablehnung greift für
Module, die ein Betreiber oder Dritte mit einer solchen Abhängigkeit hinzufügen.

Bei „erweitert um …“ läuft das Entfernen; ein Hinweis nennt das Modul, das danach ohne die
Zusatzfunktion weiterläuft.

## Datenklasse der Modell-Routen

Jeder Alias des Modell-Gateways (`papaia-chat`, `papaia-structured`, `papaia-embed` und
eigene Aliasse im Overlay) trägt die höchste Datenklasse, die über ihn an das Modell gehen
darf. Ohne Entscheidung des Betreibers ist das `intern` (`internal`). Die Klasse wird so
festgelegt:

- für alle Aliasse in der Root-`.env` mit `PAPAIA_MODEL_MAX_CLASS=<klasse>`;
- für einen einzelnen Alias im Overlay `$PAPAIA_CONFIG_DIR/overlay/ai/litellm/config.yaml`
  mit `model_info.papaia_max_class: <klasse>` (dieser Wert hat Vorrang).

Zulässig sind nur die Kennungen der Skala: `public`, `internal`, `partner_contact`,
`personal`, `employee`, `confidential`, `special`, `professional_secret`. Ein anderer Wert,
auch in anderer Schreibweise oder leer, lässt `papaia-ctl start` mit dem Alias und dem Wert
abbrechen. Ein extern gehostetes Testmodell erhält nie mehr als `internal`. Ein Wert aus
einem Add-on wird nicht übernommen und gemeldet.

Nach `papaia-ctl start` steht die Klasse im Katalog der Plattform (Block `models`) und in
der Routendatei `$PAPAIA_CONFIG_DIR/ai/litellm/model-routes.json`; jede geänderte Klasse ist
eine Zeile im Audit-Log. Die Module lesen die Klasse aus dem Katalog und lehnen Inhalte
oberhalb der Klasse ab.

`papaia-ctl addon start <modul>` warnt, wenn ein Modul für einen Alias eine höhere Klasse
angibt, als die Route zulässt; das Modul startet trotzdem. `papaia-ctl doctor
model_gateway_classes` meldet dieselben Fälle als Warnung und schlägt fehl, wenn die
Routendatei fehlt oder nicht zur Konfiguration passt; dann hilft `papaia-ctl start`.

### Ablehnung am Modell-Gateway

Das Gateway prüft jede Modellanfrage eines Moduls ein zweites Mal, bevor sie ein Modell
erreicht. Ein Modul nennt die Klasse einer Anfrage im Kopf `x-papaia-data-class`; ohne den
Kopf gilt die Klasse, die das Modul für den Alias angegeben hat, und ohne solche Angabe die
höchste Klasse (`professional_secret`). Das Gateway lehnt ab:

| Fall | Antwort |
|---|---|
| Klasse der Anfrage über der Klasse der Route oder über der angegebenen Klasse des Moduls | `403`, `class_exceeded` |
| Kopf ungültig (leer, Liste, zu lang, nicht ASCII, Steuerzeichen, nicht auf der Skala) | `400`, `invalid_data_class` |
| Routendatei fehlt, ist unlesbar oder nennt den Alias nicht | `503`, `route_class_unknown` |

Bei aktivem Not-Halt kommt zuerst `platform_halt`. Die Antwort trägt den Fehlercode im Kopf
`x-papaia-error-code` und die Korrelationskennung in `x-papaia-correlation-id`. Anfragen
mit dem Hauptschlüssel (Chat) werden nicht geprüft.

Jede Ablehnung ist eine Zeile `papaia.audit/1` in
`$PAPAIA_CONFIG_DIR/audit/outbox/litellm.jsonl` (Zähler in `litellm.seq` daneben): Modul,
Alias, Klasse der Anfrage, Fehlercode und Korrelationskennung, nie Inhalt oder Schlüssel.
`papaia-ctl start` legt beide Dateien an; Docker darf sie nicht anlegen.

Modulschlüssel erreichen nur noch die Chat- und Embedding-Routen und die Modellliste; jede
andere Route des Gateways antwortet `403`. Der erste `papaia-ctl start` nach dem Update
ersetzt deshalb jeden Modulschlüssel einmal.

Eine geänderte Klasse (oder Konfiguration) gilt am laufenden Gateway erst nach dessen
Neustart, zum Beispiel mit `docker compose restart litellm` im Projekt der Installation.
