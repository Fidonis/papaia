"""papaia-audit SIEM watch: how far behind each SIEM target is, when that is a warning or
a failure, the warning mail to the operations address, and `audit siem skip`.

Standard library only, apart from the submission check of `core`. The database work is
in `__main__.py`; this module decides, so it runs and is tested with any clock.

Rules (docs/audit.md, "SIEM"):

- There is no buffer of its own: undelivered events stay in the store, and retention
  holds them back (retention.py). The backlog of a target is what it has not taken yet,
  its lag the age of the oldest of those events.
- Lag over 60 s or a delivery failing for over 60 s is `warn`; either over 10 min is
  `fail` and sends one warning mail per outage. A target no longer configured that still
  holds events back is `warn`: only `papaia-ctl audit siem skip` releases them.
- The volume of the database: from 80 % `warn`, from 95 % `fail` (`doctor siem`); from
  95 % also one warning mail until it drops below again. The service sees the fill level
  through a read-only mount of the volume whose root it cannot read (`statvfs` only).
- One mail per outage, also across a restart: a sent mail is marked in
  `audit.alert_state` (and in memory, should the store be out of reach) before its event
  is appended, and cleared once the target or the volume is fine again.
- `audit siem skip --source --until` needs a reason of 20 to 1000 characters. The read
  positions move and the reason is kept in `audit.export_skip`; the event names source,
  target and the number released, never the reason.
- The mail goes through the stack's mail relay, one plain address per field; sending it
  is an `operation` event with effect `send`. Without mail settings (operations address
  and active relay) there is no mail and the service logs that once per outage.
"""

from __future__ import annotations

import email.message
import json
import math
import os
import re
import secrets
import smtplib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from papaia_audit import core

OK, WARN, FAIL = "ok", "warn", "fail"
LAG_WARN_SECONDS = 60
LAG_FAIL_SECONDS = 600
DISK_WARN_PERCENT = 80
DISK_FAIL_PERCENT = 95
WATCH_INTERVAL_SECONDS = 60
# The read-only mount of the papaia-audit-db volume (docker-compose.yml).
DB_VOLUME = "/var/lib/papaia-audit/db-volume"
DISK_KEY = "volume:papaia-audit-db"
OWN_SOURCE = "papaia-audit"
WRITER = "papaia-audit/siem"
REASON_MIN, REASON_MAX = 20, 1000
MAIL_TIMEOUT_SECONDS = 15
ALERT_SUBJECT = "papaia: Audit-Weiterleitung gestört"
# Hint bar text of the Manager (governance GV-06), also the body of the warning mail.
ALERT_TEXT = (
    "Audit-Weiterleitung gestört: Das Ziel {ziel} nimmt seit {dauer} keine Ereignisse an. "
    "Die Ereignisse bleiben gespeichert und werden nachgeliefert, sobald das Ziel wieder "
    "erreichbar ist; das SIEM zeigt bis dahin keine neuen Einträge. Prüfen Sie "
    "Erreichbarkeit und Zertifikat des Ziels oder führen Sie `papaia-ctl doctor siem` aus."
)
DISK_SUBJECT = "papaia: Audit-Speicher fast voll"
DISK_TEXT = (
    "Audit-Speicher fast voll: Das Volume papaia-audit-db ist zu {prozent} % belegt. "
    "Nicht zugestellte Ereignisse bleiben dort, bis das SIEM-Ziel sie annimmt; ist das "
    "Volume voll, nimmt papaia-audit keine Ereignisse mehr an. Stellen Sie die Zustellung "
    "wieder her oder vergrößern Sie das Volume und führen Sie `papaia-ctl doctor siem` aus."
)
_SOURCE_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_TARGET_RE = re.compile(
    r"^(syslog-tls|https)://[A-Za-z0-9.-]{1,253}:[0-9]{1,5}(/[A-Za-z0-9._~/-]{0,200})?$"
)
_MAIL_RE = re.compile(r"^[^@\s,;<>\"'\x00-\x1f\x7f]{1,64}@[A-Za-z0-9.-]{1,253}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


# ─────────────────────────────────────────────────────────────────────────
# health of a target
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TargetHealth:
    target: str
    active: bool
    backlog: int  # events of all sources the target has not taken
    oldest_undelivered: datetime | None  # `time` of the oldest of them
    failing_since: datetime | None  # first failed cycle of the current run of failures
    delivered_at: datetime | None  # last cycle in which the target took everything


@dataclass(frozen=True)
class Verdict:
    status: str
    text: str
    lag_seconds: int
    failing_seconds: int


def _seconds(since: datetime | None, now: datetime) -> int:
    return 0 if since is None else max(0, int((now - since).total_seconds()))


def minutes_text(seconds: int) -> str:
    return f"{max(1, seconds // 60)} min"


def assess(health: TargetHealth, now: datetime) -> Verdict:
    lag = _seconds(health.oldest_undelivered, now) if health.backlog else 0
    failing = _seconds(health.failing_since, now)
    if not health.active:
        if health.backlog:
            return Verdict(
                WARN,
                f"no longer configured, holds back {health.backlog} event(s) from retention "
                "until 'papaia-ctl audit siem skip' releases them",
                lag,
                0,
            )
        return Verdict(OK, "no longer configured, holds nothing back", lag, 0)
    worst = max(lag, failing)
    if worst > LAG_FAIL_SECONDS:
        return Verdict(FAIL, f"takes no events for {minutes_text(worst)}", lag, failing)
    if worst > LAG_WARN_SECONDS:
        return Verdict(WARN, f"{health.backlog} event(s) behind, {minutes_text(worst)}", lag,
                       failing)
    return Verdict(OK, f"{health.backlog} event(s) behind", lag, failing)


def volume_percent(path: str = DB_VOLUME, *, statvfs: Callable[[str], Any] = os.statvfs,
                   stat: Callable[[str], Any] = os.stat) -> int | None:
    """Fill level as `df` shows it (used of what is usable, rounded up); None when nothing
    is mounted there or it cannot be read."""
    try:
        if stat(path).st_dev == stat(os.path.dirname(path)).st_dev:
            return None
        found = statvfs(path)
    except OSError:
        return None
    used = (found.f_blocks - found.f_bfree) * found.f_frsize
    usable = used + found.f_bavail * found.f_frsize
    return math.ceil(100 * used / usable) if usable > 0 else None


def disk_status(percent: int) -> str:
    if percent >= DISK_FAIL_PERCENT:
        return FAIL
    if percent >= DISK_WARN_PERCENT:
        return WARN
    return OK


def metrics(healths: Iterable[TargetHealth], oldest_event: datetime | None,
            verified: Mapping[str, bool], now: datetime,
            verified_at: datetime | None = None) -> dict[str, Any]:
    """The governance GV-05/GV-06 measurements; no label names a person. `verified` is the
    last hourly verification, `verified_at` when it ran (None: not yet)."""
    healths = list(healths)
    return {
        "papaia_audit_export_lag_seconds": {
            h.target: assess(h, now).lag_seconds for h in healths if h.active
        },
        "papaia_audit_export_backlog": {h.target: h.backlog for h in healths if h.active},
        "papaia_audit_oldest_event_age_days": (
            None if oldest_event is None else _seconds(oldest_event, now) // 86400
        ),
        "papaia_audit_verify_ok": {source: int(ok) for source, ok in sorted(verified.items())},
        "papaia_audit_verify_age_seconds": (
            None if verified_at is None else _seconds(verified_at, now)
        ),
    }


def report(healths: Iterable[TargetHealth], oldest_event: datetime | None,
           verified: Mapping[str, bool], now: datetime,
           verified_at: datetime | None = None) -> dict[str, Any]:
    """What `python -m papaia_audit siem-status` prints and `doctor siem` reads."""
    healths = list(healths)
    targets = []
    for health in healths:
        verdict = assess(health, now)
        targets.append({
            "target": health.target,
            "active": health.active,
            "status": verdict.status,
            "text": verdict.text,
            "backlog": health.backlog,
            "lag_seconds": verdict.lag_seconds,
            "failing_seconds": verdict.failing_seconds,
        })
    return {"targets": targets,
            "metrics": metrics(healths, oldest_event, verified, now, verified_at)}


# ─────────────────────────────────────────────────────────────────────────
# warning mail
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MailSettings:
    host: str
    port: int
    to: str
    sender: str


def parse_mail(relay: str | None, to: str | None, sender: str | None) -> MailSettings | None:
    """`PAPAIA_AUDIT_MAIL_RELAY` (host:port), `..._ALERT_TO`, `..._ALERT_FROM`: all three or
    none; each address one plain address (it goes into a header line)."""
    values = [(v or "").strip() for v in (relay, to, sender)]
    if not any(values):
        return None
    relay_text, to_text, sender_text = values
    host, _, port = relay_text.rpartition(":")
    if not _HOST_RE.match(host) or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("PAPAIA_AUDIT_MAIL_RELAY must be host:port")
    for name, value in (("PAPAIA_AUDIT_ALERT_TO", to_text), ("PAPAIA_AUDIT_ALERT_FROM",
                                                              sender_text)):
        if not _MAIL_RE.match(value):
            raise ValueError(f"{name} must be one mail address")
    return MailSettings(host, int(port), to_text, sender_text)


class Mailer(Protocol):
    def send(self, subject: str, text: str) -> None: ...


class SmtpMailer:
    """Plain SMTP to the stack's mail relay, without login, as every service sends."""

    def __init__(self, settings: MailSettings) -> None:
        self.settings = settings

    def send(self, subject: str, text: str) -> None:
        message = email.message.EmailMessage()
        message["From"], message["To"] = self.settings.sender, self.settings.to
        message["Subject"] = subject
        message.set_content(text)
        with smtplib.SMTP(self.settings.host, self.settings.port,
                          timeout=MAIL_TIMEOUT_SECONDS) as smtp:
            smtp.send_message(message, from_addr=self.settings.sender,
                              to_addrs=[self.settings.to])


def duration_text(seconds: int) -> str:
    minutes = max(1, seconds // 60)
    if minutes < 120:
        return f"{minutes} Minuten"
    return f"{minutes // 60} Stunden"


def alert_text(target: str, seconds: int) -> str:
    return ALERT_TEXT.format(ziel=target, dauer=duration_text(seconds))


def disk_text(percent: int) -> str:
    return DISK_TEXT.format(prozent=percent)


def _time_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _own(check: core.SubmissionCheck, body: dict[str, Any]) -> str:
    _, canonical = check.check(json.dumps(body).encode("utf-8"), OWN_SOURCE)
    return canonical.decode("utf-8")


def alert_event(check: core.SubmissionCheck, *, target: str, sent: bool, moment: datetime,
                source_seq: int, correlation_id: str) -> str:
    """The warning mail as the send it is: an `operation` of papaia-audit itself."""
    return _mail_event(check, catalog_id="papaia-audit.siem", operation="siem.alert_mail",
                       ref={"type": "siem_target", "id": target}, sent=sent, moment=moment,
                       source_seq=source_seq, correlation_id=correlation_id)


def disk_event(check: core.SubmissionCheck, *, sent: bool, moment: datetime, source_seq: int,
               correlation_id: str) -> str:
    """The warning mail about the full volume of the store."""
    return _mail_event(check, catalog_id="papaia-audit.store",
                       operation="store.disk_alert_mail",
                       ref={"type": "volume", "id": "papaia-audit-db"}, sent=sent,
                       moment=moment, source_seq=source_seq, correlation_id=correlation_id)


def _mail_event(check: core.SubmissionCheck, *, catalog_id: str, operation: str,
                ref: dict[str, str], sent: bool, moment: datetime, source_seq: int,
                correlation_id: str) -> str:
    return _own(check, {
        "format": core.FORMAT,
        "time": _time_text(moment),
        "source_seq": source_seq,
        "correlation_id": correlation_id,
        "writer": WRITER,
        "role": "caller",
        "sub": OWN_SOURCE,
        "identity_kind": "service",
        "service_account": OWN_SOURCE,
        "azp": OWN_SOURCE,
        "catalog_id": catalog_id,
        "operation": operation,
        "effect": "send",
        "object_ref": ref,
        "result": "allowed" if sent else "error",
        "error_code": None if sent else "mail_not_sent",
        "event": "operation",
    })


class AlertState(Protocol):
    """The outages already mailed, kept in the store (`audit.alert_state`)."""

    def raised(self) -> set[str]: ...

    def mark(self, key: str) -> None: ...

    def clear(self, keys: set[str]) -> None: ...


@dataclass(frozen=True)
class _Alert:
    key: str
    subject: str
    text: str
    event: Callable[..., str]


class Watch:
    """Every minute: the health of each active target and the fill level of the store's
    volume; one mail when a target turns `fail` or the volume reaches 95 %, again only
    after it recovered, also across a restart (`state`). A mail the relay refuses is
    recorded as error and tried again the next minute."""

    def __init__(self, healths: Callable[[], list[TargetHealth]], mailer: Mailer | None,
                 append: Callable[[Callable[[int], str]], object], check: core.SubmissionCheck,
                 log: Callable[[str], None], *, disk: Callable[[], int | None] | None = None,
                 state: AlertState | None = None) -> None:
        self.healths, self.mailer, self.append = healths, mailer, append
        self.check, self.log = check, log
        self.disk, self.state = disk, state
        self.mailed: set[str] = set()
        self.noted: set[str] = set()

    def _alerts(self, now: datetime) -> dict[str, _Alert]:
        alerts: dict[str, _Alert] = {}
        for health in self.healths():
            verdict = assess(health, now)
            if health.active and verdict.status == FAIL:
                seconds = max(verdict.lag_seconds, verdict.failing_seconds)
                alerts[health.target] = _Alert(
                    health.target, ALERT_SUBJECT, alert_text(health.target, seconds),
                    lambda target=health.target, **kw: alert_event(self.check, target=target,
                                                                   **kw),
                )
        percent = self.disk() if self.disk is not None else None
        if percent is not None and disk_status(percent) == FAIL:
            alerts[DISK_KEY] = _Alert(DISK_KEY, DISK_SUBJECT, disk_text(percent),
                                      lambda **kw: disk_event(self.check, **kw))
        return alerts

    def _kept(self, alerts: dict[str, _Alert]) -> set[str]:
        if self.state is None:
            return set()
        try:
            kept = self.state.raised()
            if kept - set(alerts):
                self.state.clear(kept - set(alerts))
        except Exception as error:  # noqa: BLE001 - the memory still holds this run's mails
            self.log(f"siem alert state not read ({type(error).__name__})")
            return set()
        return kept & set(alerts)

    def _mark(self, key: str) -> None:
        self.mailed.add(key)
        if self.state is not None:
            try:
                self.state.mark(key)
            except Exception as error:  # noqa: BLE001 - kept in memory until a restart
                self.log(f"siem alert state not kept ({type(error).__name__})")

    def run(self, now: datetime) -> None:
        alerts = self._alerts(now)
        self.mailed &= set(alerts)
        self.noted &= set(alerts)
        self.mailed |= self._kept(alerts)
        for key, alert in alerts.items():
            if key in self.mailed:
                continue
            if self.mailer is None:
                if key not in self.noted:
                    self.noted.add(key)
                    self.log(f"siem alert {key} fail, no mail settings (PAPAIA_OPERATIONS_MAIL"
                             " and the smtp relay)")
                continue
            try:
                self.mailer.send(alert.subject, alert.text)
                sent = True
            except (OSError, smtplib.SMTPException) as error:
                sent = False
                self.log(f"siem alert {key} warning mail not sent ({type(error).__name__})")
            correlation_id = "siem-alert-" + secrets.token_hex(12)
            try:
                if sent:
                    # Before the event: a store that refuses it must not bring a mail a minute.
                    self._mark(key)
                    self.log(f"siem alert {key} fail, warning mail sent")
            finally:
                self.append(lambda seq, sent=sent, alert=alert, cid=correlation_id: alert.event(
                    sent=sent, moment=now, source_seq=seq, correlation_id=cid,
                ))


# ─────────────────────────────────────────────────────────────────────────
# audit siem skip
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Skip:
    source: str
    until: int
    reason: str
    target: str | None


def check_reason(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("audit siem skip needs a reason (20 to 1000 characters)")
    text = value.strip()
    if not REASON_MIN <= len(text) <= REASON_MAX or any(
        (ord(c) < 32 and c not in "\n\t") or ord(c) == 127 for c in text
    ):
        raise ValueError("audit siem skip needs a reason (20 to 1000 characters)")
    return text


def parse_skip(document: object) -> Skip:
    """The request on stdin of `siem-skip`, checked again inside the service."""
    if not isinstance(document, dict) or set(document) != {"source", "until", "reason", "target"}:
        raise ValueError("audit siem skip takes source, until, reason and target")
    source, until, target = document["source"], document["until"], document["target"]
    if not isinstance(source, str) or not _SOURCE_RE.fullmatch(source):
        raise ValueError("audit siem skip needs a source name")
    if isinstance(until, bool) or not isinstance(until, int) or until < 1:
        raise ValueError("audit siem skip needs --until, a seq of 1 or more")
    if target is not None and (not isinstance(target, str) or not _TARGET_RE.fullmatch(target)):
        raise ValueError("audit siem skip --target must name a target as doctor siem shows it")
    return Skip(source, until, check_reason(document["reason"]), target)


def skip_event(check: core.SubmissionCheck, *, source: str, target: str, released: int,
               moment: datetime, source_seq: int, correlation_id: str) -> str:
    """A read position moved by the operator: a settings change that discards deliveries."""
    return _own(check, {
        "format": core.FORMAT,
        "time": _time_text(moment),
        "source_seq": source_seq,
        "correlation_id": correlation_id,
        "writer": WRITER,
        "role": None,
        "sub": None,
        "identity_kind": "service",
        "service_account": OWN_SOURCE,
        "azp": None,
        "catalog_id": None,
        "operation": "siem.skip",
        "effect": "delete",
        "object_ref": {"type": "siem_position", "id": f"{source}@{target}"},
        "result": "allowed",
        "detail": {"count": released},
        "event": "config_changed",
    })
