"""papaia-audit retention: which events a run removes, and the event that records it.

Standard library only, apart from the submission check of `core`. The database work is
in `__main__.py` (and, authoritative, in `audit.prune` of schema_retention.sql, which
checks the same limits again); this module decides, so it runs and is tested with any
clock.

Rules (docs/audit.md, "Retention"):

- Events are kept `PAPAIA_AUDIT_RETENTION_MONTHS` months (default 12, 6 to 36), counted
  from their `time`, the business timestamp of the source.
- A chain is only ever shortened at its start. A run removes, per source, the longest
  run of events from the start that are all older than the limit, and stops early:
  - before the oldest event of a person under a deletion lock (`legal_hold`), and
  - after the last event every SIEM target has received (`siem_undelivered`); a target
    that is no longer configured keeps holding back until `audit siem skip` releases it.
- The last removed event becomes the source's anchor: `seq` and `hash` from which
  `verify` continues. Every run writes one `retention_run` event per source with an
  anchor or a hold into the chain of `papaia-audit`; its `object_ref` names the anchor,
  so a changed anchor shows up in `verify`.
- When the store refuses the removal of one source (`audit.prune` checks again, against
  its own clock and the locks of that moment), that source keeps everything this run and
  gets a `retention_run` event held back with `store_refused`; the other sources go on.
"""

from __future__ import annotations

import calendar
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from papaia_audit import core, siem

DEFAULT_MONTHS = 12
MIN_MONTHS = 6
MAX_MONTHS = 36
OWN_SOURCE = "papaia-audit"
WRITER = "papaia-audit/retention"
ANCHOR_REF = "audit_anchor"
SOURCE_REF = "audit_source"
LEGAL_HOLD = "legal_hold"
UNDELIVERED = "siem_undelivered"
REFUSED = "store_refused"
# `operation` of a retention_run event: what limited the run of that source.
OPERATIONS = {
    None: "retention.prune",
    LEGAL_HOLD: "retention.held_back.legal_hold",
    UNDELIVERED: "retention.held_back.siem_undelivered",
    REFUSED: "retention.held_back.store_refused",
}


class PruneRefused(Exception):
    """The store refused to remove events of one source (`audit.prune`, SQLSTATE PA002)."""


def parse_months(text: str | None) -> int:
    """The configured retention in months; ValueError outside 6..36 or not a number."""
    value = (text or "").strip()
    if not value:
        return DEFAULT_MONTHS
    if not value.isascii() or not value.isdigit() or len(value) > 2:
        raise ValueError("PAPAIA_AUDIT_RETENTION_MONTHS must be a whole number of months")
    months = int(value)
    if not MIN_MONTHS <= months <= MAX_MONTHS:
        raise ValueError(
            f"PAPAIA_AUDIT_RETENTION_MONTHS must be between {MIN_MONTHS} and {MAX_MONTHS}"
        )
    return months


def cutoff(now: datetime, months: int) -> datetime:
    """`now` minus `months` calendar months (the day clamped to the month's last day), in
    UTC. Events with a `time` before it are past the limit; one at it is kept."""
    if not MIN_MONTHS <= months <= MAX_MONTHS:
        raise ValueError("months out of range")
    moment = now.astimezone(timezone.utc)
    index = moment.year * 12 + moment.month - 1 - months
    year, month = divmod(index, 12)
    day = min(moment.day, calendar.monthrange(year, month + 1)[1])
    return moment.replace(year=year, month=month + 1, day=day)


@dataclass(frozen=True)
class Facts:
    """What the store says about one source before a run."""

    old_end: int  # last seq of the leading run of events older than the cutoff, 0 if none
    anchor_seq: int  # seq of the last removed event, 0 if nothing was removed yet
    first_held: int | None  # seq of the oldest event of a person under a deletion lock
    delivered: int | None  # lowest seq every SIEM target has received; None: no target


@dataclass(frozen=True)
class Plan:
    source: str
    upto: int  # remove every event up to this seq; equal to the anchor: remove nothing
    anchor_seq: int
    held_back: str | None

    @property
    def removes(self) -> bool:
        return self.upto > self.anchor_seq


def plan(source: str, facts: Facts) -> Plan:
    upto, held_back = facts.old_end, None
    if facts.first_held is not None and facts.first_held - 1 < upto:
        upto, held_back = facts.first_held - 1, LEGAL_HOLD
    if facts.delivered is not None and facts.delivered < upto:
        upto, held_back = facts.delivered, UNDELIVERED
    return Plan(source, max(upto, facts.anchor_seq), facts.anchor_seq, held_back)


@dataclass(frozen=True)
class Pruned:
    """The result of `audit.prune`: removed events and the source's anchor after it."""

    removed: int
    anchor_seq: int
    anchor_hash: bytes | None


def anchor_ref(source: str, seq: int, digest: bytes) -> str:
    return f"{source}:{seq}:{digest.hex()}"


class Store(Protocol):
    def sources(self) -> list[str]:
        """Every source with events or an anchor."""
        ...

    def facts(self, source: str, before: datetime) -> Facts: ...

    def prune(
        self, source: str, upto: int, months: int, build: Callable[[Pruned, int], str]
    ) -> Pruned:
        """In one transaction: remove up to `upto` (nothing when it is the anchor), then
        append `build(result, source_seq)` to the chain of papaia-audit. PruneRefused, with
        nothing changed, when the store refuses the removal."""
        ...


def time_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_correlation_id() -> str:
    return "retention-" + secrets.token_hex(12)


def own_event(
    check: core.SubmissionCheck,
    *,
    event: str,
    moment: datetime,
    source_seq: int,
    correlation_id: str,
    writer: str = WRITER,
    effect: str,
    object_ref: dict[str, str] | None,
    operation: str | None,
    count: int | None = None,
) -> str:
    """One event of papaia-audit itself, checked like any submission, in canonical form."""
    body = {
        "format": core.FORMAT,
        "time": time_text(moment),
        "source_seq": source_seq,
        "correlation_id": correlation_id,
        "writer": writer,
        "role": None,
        "sub": None,
        "identity_kind": "service",
        "service_account": OWN_SOURCE,
        "azp": None,
        "catalog_id": None,
        "operation": operation,
        "effect": effect,
        "object_ref": object_ref,
        "result": "allowed",
        "detail": {"count": count} if count is not None else None,
        "event": event,
    }
    _, canonical = check.check(json.dumps(body).encode("utf-8"), OWN_SOURCE)
    return canonical.decode("utf-8")


def changed_settings(current: dict[str, str], stored: dict[str, str]) -> list[str]:
    """Keys whose value differs from the one the store recorded (or that it lacks)."""
    return sorted(key for key, value in current.items() if stored.get(key) != value)


@dataclass(frozen=True)
class RunReport:
    plans: list[Plan]
    removed: dict[str, int]


def run(
    store: Store,
    check: core.SubmissionCheck,
    months: int,
    clock: Callable[[], datetime],
) -> RunReport:
    """One retention run. `clock` gives the time against which the business timestamps
    of the events are judged and the time of the run's own events."""
    now = clock()
    before = cutoff(now, months)
    correlation_id = new_correlation_id()
    # papaia-audit last: the runs of the other sources append to its chain.
    names = sorted(store.sources(), key=lambda name: (name == OWN_SOURCE, name))
    plans, removed = [], {}
    for source in names:
        current = plan(source, store.facts(source, before))
        plans.append(current)
        if not current.removes and current.anchor_seq == 0 and current.held_back is None:
            continue

        def builder(current: Plan) -> Callable[[Pruned, int], str]:
            def build(result: Pruned, source_seq: int) -> str:
                ref = (
                    {"type": ANCHOR_REF, "id": anchor_ref(current.source, result.anchor_seq,
                                                          result.anchor_hash)}
                    if result.anchor_hash is not None
                    else {"type": SOURCE_REF, "id": current.source}
                )
                return own_event(
                    check,
                    event="retention_run",
                    moment=now,
                    source_seq=source_seq,
                    correlation_id=correlation_id,
                    effect="delete",
                    object_ref=ref,
                    operation=OPERATIONS[current.held_back],
                    count=result.removed,
                )

            return build

        try:
            removed[source] = store.prune(source, current.upto, months, builder(current)).removed
        except PruneRefused:
            # Keep everything of this source until the next run, and record why.
            current = Plan(source, current.anchor_seq, current.anchor_seq, REFUSED)
            plans[-1] = current
            removed[source] = store.prune(source, current.upto, months, builder(current)).removed
    return RunReport(plans, removed)


# ─────────────────────────────────────────────────────────────────────────
# schedule of the service
# ─────────────────────────────────────────────────────────────────────────

RUN_AT = (3, 30)  # daily retention run, UTC
WATCH_SECONDS = 60  # the SIEM targets' backlog


def next_hour(now: datetime) -> datetime:
    """The next full hour after `now` (UTC): heads are signed and chains verified then."""
    moment = now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    return moment + timedelta(hours=1)


def next_run(now: datetime) -> datetime:
    """The next 03:30 UTC after `now`."""
    moment = now.astimezone(timezone.utc)
    hour, minute = RUN_AT
    candidate = moment.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return candidate if candidate > moment else candidate + timedelta(days=1)


@dataclass(frozen=True)
class Duties:
    """What the service's upkeep runs; each one fails on its own."""

    record: Callable[[], None]  # settings and the SIEM targets' read positions
    export: Callable[[], int] | None  # one export cycle; None without a SIEM target
    sign: Callable[[], dict[str, Any]]  # the signed heads of every chain
    keep: Callable[[dict[str, Any]], object]  # the heads to the backup target
    verify: Callable[[], None]  # every chain, one log line per source
    send_heads: Callable[[dict[str, Any]], None] | None  # the heads to the SIEM target
    retain: Callable[[], object]  # one retention run
    # how far behind the SIEM targets are, with the warning mail; None without a target
    watch: Callable[[datetime], None] | None = None


class Schedule:
    """Every few seconds `tick`: the SIEM export; every minute how far behind the targets
    are (with the warning mail); every full hour the signed heads, kept at
    the backup target before anything else, and the verification of every chain; daily
    the retention run. A failure of one duty (an unreachable SIEM target, the database)
    is logged and skips no other one: the heads at the backup target are needed most when
    the SIEM is down. Export and retention wait until the settings are recorded, so a new
    target's read positions hold events back before anything is removed."""

    def __init__(self, duties: Duties, now: datetime, log: Callable[[str], None],
                 target: str = "") -> None:
        self.duties, self.log, self.target = duties, log, target
        self.recorded = False
        self.due_heads, self.due_retention = next_hour(now), next_run(now)
        self.due_watch = now

    def _run(self, name: str, action: Callable[[], object]) -> bool:
        try:
            action()
        except siem.ExportError as error:
            self.log(f"siem target={self.target} not delivered ({error})")
        except Exception as error:  # noqa: BLE001 - one duty must not stop the others
            self.log(f"upkeep {name} failed ({type(error).__name__})")
        else:
            return True
        return False

    def _export(self) -> None:
        assert self.duties.export is not None
        sent = self.duties.export()
        if sent:
            self.log(f"siem target={self.target} sent={sent}")

    def hourly(self) -> None:
        heads: list[dict[str, Any]] = []

        def keep() -> None:
            heads.append(self.duties.sign())
            self.duties.keep(heads[0])

        kept = self._run("heads", keep)
        self._run("verify", self.duties.verify)
        send = self.duties.send_heads
        if kept and send is not None:
            self._run("export", lambda: send(heads[0]))

    def tick(self, now: datetime) -> None:
        if not self.recorded:
            self.recorded = self._run("settings", self.duties.record)
        if self.recorded and self.duties.export is not None:
            self._run("export", self._export)
        watch = self.duties.watch
        if self.recorded and watch is not None and now >= self.due_watch:
            self.due_watch = now + timedelta(seconds=WATCH_SECONDS)
            self._run("watch", lambda: watch(now))
        if now >= self.due_heads:
            self.due_heads = next_hour(now)
            self.hourly()
        if self.recorded and now >= self.due_retention:
            self.due_retention = next_run(now)
            self._run("retention", self.duties.retain)
