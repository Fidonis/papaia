# Mail-Antwortdatei bei der Neuinstallation

Dieses Dokument beschreibt für den Betrieb, wie die Neuinstallation den Mailserver der
Plattform aus einer Antwortdatei liest (Frage 9 der Fragerunde von `papaia-ctl setup`, siehe
README, Abschnitt „Question round“) und was danach mit der Datei geschieht.

## Format

Die Datei `smtp.env` enthält die Adresse des Mailservers und sein Kennwort, eine Angabe je
Zeile, Kommentare mit `#`:

```ini
SMTP_URL=smtp+starttls://relay-user@mail.example.org:587
SMTP_PASSWORD=<Kennwort von relay-user>
# SMTP_FROM=papaia@example.org
```

- `smtp+starttls://` verbindet unverschlüsselt und schaltet mit STARTTLS auf TLS um
  (Standardport 587), `smtps://` spricht TLS ab dem ersten Byte (Port 465), `smtp://` ist
  unverschlüsselt und erlaubt keine Anmeldung (Port 25).
- Der Benutzername steht in der URL, das Kennwort nur in `SMTP_PASSWORD`. Eine URL mit
  Kennwort wird abgelehnt.
- `SMTP_FROM` ist der Absender; ohne Angabe gilt `papaia@<Basisdomain>`.
- Andere Schlüssel werden abgelehnt.

Die Datei gehört dem Betreiber und ist nur für ihn lesbar:

```sh
chmod 600 /root/papaia-answers/smtp.env
```

In der Antwortdatei der Fragerunde steht nur ihr Pfad (`mail: /root/papaia-answers/smtp.env`)
oder `none` für eine Installation ohne Mailversand.

## Prüfung während `setup`

`setup` prüft die Datei sofort, bevor etwas geschrieben wird:

1. Rechte: Eine Datei, die Gruppe oder andere lesen dürfen, wird abgelehnt (`chmod 600`).
2. Form: URL, Port, Benutzername, Kennwort und Absender.
3. Mailserver: Verbindung, STARTTLS oder TLS und die Anmeldung, wie das Mail-Relais sie
   später ausführt. Es wird keine Mail versendet.

Besteht die Datei eine Prüfung nicht, fragt `setup` am Terminal nur diese Frage noch einmal.
Ohne Terminal (`setup --answers=DATEI -y`) nennt `setup` den Fehler und ändert nichts
(Exitcode 2). Ist der Mailserver bei der Installation noch nicht erreichbar, lautet die
Antwort `none`; den Mailversand schaltet später `papaia-ctl setup --smtp` ein.

Das Kennwort wird nie angezeigt und nie protokolliert. Es geht aus der Datei direkt in den
Geheimnisspeicher des Mail-Relais (`infra/smtp-relay/upstream-password`, Modus 0600). Die
Datei selbst wird nicht kopiert; `setup-answers.yaml` enthält nur ihren Pfad.

## Nach der Einrichtung löschen

Am Ende von `setup` fordert eine Warnung auf, die Datei zu löschen, denn das Relais hat das
Kennwort jetzt selbst:

```sh
rm /root/papaia-answers/smtp.env
```

Solange die Datei besteht, meldet `papaia-ctl doctor mail_answer_file` den Status `warn`.
Nach dem Löschen meldet die Prüfung `pass`. Sie liest nur den Pfad und ob die Datei noch
besteht, nie ihren Inhalt.

Ein neues Kennwort setzt später `PAPAIA_SMTP_PASSWORD='<Kennwort>' papaia-ctl setup --smtp`
(README, Abschnitt „Outbound mail“); eine neue Antwortdatei ist dafür nicht nötig.
