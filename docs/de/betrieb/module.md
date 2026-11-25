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
# als zweites Konto des Hosts, nicht dasselbe wie oben:
papaia-ctl pairing approve --client=papaia-me --audience=papaia-connections --effects=rd
papaia-ctl start
```

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
