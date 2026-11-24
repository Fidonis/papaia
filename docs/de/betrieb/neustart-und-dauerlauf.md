# Neustart und Dauerlauf

papAIa läuft auf einem Host ohne Hochverfügbarkeit. Ein Neustart des Hosts, von Docker oder
eines Containers braucht keinen Handgriff; dieses Kapitel beschreibt, was dabei geschieht und
worauf im Dauerbetrieb zu achten ist.

## Vorbereitung des Hosts

- Docker startet mit dem Betriebssystem: unter Linux `systemctl enable docker`, unter Docker
  Desktop die Einstellung „Start Docker Desktop when you sign in“ mit automatischer Anmeldung
  des Kontos, unter dem Docker Desktop läuft.
- Das Sicherungsziel wird beim Start eingehängt (Eintrag in `/etc/fstab` bzw. Automount),
  bevor Docker startet. Ohne Sicherungsziel bleibt die Plattform nach dem Start geschlossen
  (siehe [§S-10](stoerungen.md#s-10-datenstand-älter-als-das-löschjournal)).
- Die Uhr des Hosts wird über NTP gestellt (Matrixzeile K-13);
  `papaia-ctl doctor time_sync` prüft das.

## Was beim Neustart geschieht

Alle Dienste tragen die Neustartregel `unless-stopped`; einmalige Einrichtungscontainer
tragen `"no"` und laufen einmal, wenn der Stapel gestartet wird. Nach einem Neustart des Hosts oder
des Docker-Dienstes startet Docker daher jeden Dienst, der vorher lief, und keinen, den der
Betrieb mit `papaia-ctl stop` angehalten hat.

1. Der Rand zeigt eine Wartungsseite, bis `papaia-lifecycle` den Datenstand gegen das
   Löschjournal am Sicherungsziel geprüft hat (Startsperre, Kennung `CORE-STARTGATE-CHECK`).
   Ohne Rückstand öffnet die Sperre selbst.
2. Der Zustand jedes Dienstes liegt in benannten Volumes (siehe [Größe und Profile](groesse.md))
   und übersteht den Neustart.
3. Anmeldungen bleiben nicht erhalten, wo ein Dienst seine Sitzungen nur im Speicher hält: Mein
   Bereich hält keinen eigenen Zustand, seine Sitzungen überstehen keinen Neustart, und er
   läuft in genau einer Instanz. Die Personen melden sich neu an.

Prüfen, ob alles wieder läuft:

```sh
papaia-ctl status
papaia-ctl doctor
```

`status` zeigt je Modul und Container den Zustand; ein Dienst mit Zustand `missing` wurde
nicht gestartet. Ein Neustart einzelner Container (`docker restart <container>`) wirkt wie ein
kurzer Ausfall dieses Dienstes: Bis zu seiner Rückkehr fehlen die Funktionen, die ihn
brauchen. Bleibt ein Dienst danach ungesund, nennt `papaia-ctl doctor` den Abschnitt des
[Störungsleitfadens](stoerungen.md).

Geordnet anhalten und wieder starten:

```sh
papaia-ctl stop --addons
papaia-ctl start
```

## Dauerbetrieb

| Was wächst | Grenze | Prüfung |
|---|---|---|
| Protokolle der Container | je Container höchstens 5 Dateien zu 10 MiB (50 MiB), für alle Kern-Profile zusammen höchstens 2450 MiB (49 Container zu je 50 MiB); je Modul-Container 50 MiB dazu | `papaia-ctl logs <dienst>` |
| Audit-Log | Aufbewahrung nach `PAPAIA_AUDIT_RETENTION_MONTHS` (siehe [Protokollierung](../datenschutz/protokollierung.md)) | `papaia-ctl audit retention` |
| Sicherungen am Ziel | Aufbewahrung nach `backup --keep` bzw. `--retention-period-days` | `papaia-ctl backup target check`, `backup.log` am Ziel |
| Docker-Speicher (Images, Volumes, Build-Reste) | freie Platte laut Größenprofil | `papaia-ctl doctor docker_usage`, `papaia-ctl doctor disk_space` |
| Zertifikate | Erneuerung vor Ablauf | `papaia-ctl certs status`, `papaia-ctl doctor certs` |

- Eine tägliche Sicherung gehört zum Dauerbetrieb: im Manager auf der Seite „Sicherung“ oder
  mit einem systemd-Timer (README, Abschnitt `backup`).
- `papaia-ctl metrics --out=<datei>` schreibt die Messwerte im Textformat für gängige Sammler;
  `papaia-ctl support-bundle` bündelt `doctor`, `status` und Protokolle ohne Geheimnisse für
  eine Rückfrage.
