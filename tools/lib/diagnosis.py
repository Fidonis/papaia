"""The cause behind a failing `doctor` check, in one German sentence (BE-26, BE-29).

`doctor` reports what it measured, in English, as every check always has. Operators of a
German installation read the troubleshooting guide in German, so each `fail` row also
carries one sentence that names the cause and the section of the guide (`siehe Handbuch
§S-n`). The sentences are the patterns of the nine injected faults (operations
handbook, sections S-1 to S-9):

    S-1  model gateway stopped                 container_health, model_gateway
    S-2  model not loaded                      model_ready
    S-3  identity service stopped              container_health
    S-4  database of a module stopped          container_health
    S-5  emergency halt set                    halt
    S-6  scope assignment of a client removed  realm
    S-7  data disk full                        disk_space
    S-8  certificate expired                   certs
    S-9  mail server not reachable             smtp

A failing check none of them explains gets a general sentence that points at the
diagnosis section of the guide. Nothing here probes anything: the sentences are built
from the check results and the container states `status` already read, so they never
disagree with the rows above them. The texts carry no secret and no content: host names,
paths, module names, client and scope names, dates and counts only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import kit_names, status

GUIDE = "Handbuch"
GENERAL_SECTION = "Diagnose"

# Display names of the modules as the glossary writes them (RE-18).
MODULE_NAMES = {
    "assist": "Assistant",
    "studio": "Studio",
    "flow": "Flow",
    "me": "Me",
    "data": "Data",
    "connections": "Connections",
    "paperless": "Paperless",
    "knowledge-map": "Wissenslandkarte",
}

# Roles (`de.fidonis.role`) of the core services the sentences name.
GATEWAY_ROLE = "llm-proxy"
IDENTITY_ROLE = "identity-provider"
DATABASE_ROLE = "database"
# Add-ons need not label their services; a database is then known by its service name.
_DATABASE_SERVICE = re.compile(r"(?:^|[-_])(?:db|database|postgres(?:ql)?|mariadb|mysql|mssql)$")

_DOWN = frozenset({status.Health.STOPPED, status.Health.UNHEALTHY})
# `realm sync --check` names a missing scope assignment this way (lib/realm_sync.py).
_MISSING_SCOPE = re.compile(
    r"^fail: client (?P<client>[^\s:]+): (?:default|optional) scope (?P<scope>\S+) added$"
)
# Anything shown in a sentence: printable, no line break, bounded.
_SHOWN_MAX = 120
_PATH_MAX = 1024


@dataclass(frozen=True)
class Cause:
    text: str
    section: str | None  # "S-1" ... "S-9"; None: the general diagnosis section

    @property
    def reference(self) -> str:
        if self.section is None:
            return f"siehe {GUIDE}, Abschnitt {GENERAL_SECTION}"
        return f"siehe {GUIDE} §{self.section}"

    def line(self) -> str:
        return f"{self.text} ({self.reference})"

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "section": self.section, "reference": self.reference}


def _shown(value: object, limit: int = _SHOWN_MAX) -> str:
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def module_name(raw: str) -> str:
    """`papaia-assist`, `assist` -> `Assistant`; unknown names as they are."""
    bare = raw.removeprefix("papaia-")
    return MODULE_NAMES.get(bare, _shown(bare))


def _date(value: str | int | None) -> str:
    """An ISO time or an epoch as `27.09.2026`; empty when unreadable."""
    try:
        if isinstance(value, int):
            moment = datetime.fromtimestamp(value, timezone.utc)
        else:
            moment = datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return ""
    return moment.strftime("%d.%m.%Y")


def _time(value: int | None) -> str:
    if value is None:
        return "unbekannter Zeit"
    try:
        moment = datetime.fromtimestamp(value, timezone.utc)
    except (OSError, OverflowError, ValueError):
        return "unbekannter Zeit"
    return moment.strftime("%d.%m.%Y %H:%M UTC")


# ─── container states ────────────────────────────────────────────────────


def _down_containers(
    report: status.StatusReport | None,
) -> list[tuple[status.Module, status.Container]]:
    if report is None or not report.docker.reachable:
        return []
    return [
        (module, container)
        for module in report.modules
        for container in module.containers
        if container.health in _DOWN
    ]


def _is_database(container: status.Container) -> bool:
    return container.role == DATABASE_ROLE or bool(_DATABASE_SERVICE.search(container.service))


def container_causes(report: status.StatusReport | None) -> list[Cause]:
    causes: list[Cause] = []
    seen: set[str] = set()

    def add(cause: Cause) -> None:
        if cause.text not in seen:
            seen.add(cause.text)
            causes.append(cause)

    for module, container in _down_containers(report):
        if container.role == GATEWAY_ROLE or container.service == "litellm":
            add(Cause(
                "Das Modell-Gateway (LiteLLM) läuft nicht; Module können keine Modelle nutzen.",
                "S-1",
            ))
        elif container.role == IDENTITY_ROLE or container.service == "keycloak":
            add(Cause(
                "Der Anmeldedienst (Keycloak) ist nicht erreichbar; niemand kann sich anmelden.",
                "S-3",
            ))
        elif _is_database(container):
            owner = module.compose_project if module.kind == "addon" else module.name
            add(Cause(f"Die Datenbank von {module_name(owner)} läuft nicht.", "S-4"))
    return causes


# ─── per check ───────────────────────────────────────────────────────────


def _disk(details: dict[str, Any]) -> list[Cause]:
    causes = []
    for item in details.get("paths") or []:
        if item.get("status") != "fail":
            continue
        path = _shown(item.get("path", "?"), _PATH_MAX)
        free, total = item.get("free_bytes"), item.get("total_bytes")
        if isinstance(free, int) and isinstance(total, int) and total and free * 100 < total:
            text = f"Auf {path} ist kein Platz mehr; Schreiben ist gestoppt."
        else:
            text = f"Auf {path} wird der Platz knapp; Schreiben kann jederzeit stoppen."
        causes.append(Cause(text, "S-7"))
    return causes


_CERT_HOST = re.compile(r"(?:^|/)live/(?P<host>[^/]+)/fullchain\.pem$|(?:^|/)(?P<file>[^/]+)\.crt$")


def _cert_host(path: str) -> str:
    found = _CERT_HOST.search(path)
    if found:
        return _shown(found.group("host") or found.group("file"))
    return _shown(path)


def _certs(details: dict[str, Any]) -> list[Cause]:
    causes = []
    for item in details.get("certificates") or []:
        if item.get("status") != "fail":
            continue
        host, when = _cert_host(str(item.get("path", "?"))), _date(item.get("not_after"))
        if isinstance(item.get("days_left"), int) and item["days_left"] < 0:
            text = f"Das Zertifikat für {host} ist seit {when} abgelaufen."
        else:
            text = f"Das Zertifikat für {host} läuft am {when} ab."
        causes.append(Cause(text, "S-8"))
    return causes


def _smtp(details: dict[str, Any]) -> list[Cause]:
    queued = details.get("queued")
    waiting = queued if isinstance(queued, int) else 0
    host = _shown(f"{details.get('host', '?')}:{details.get('port') or '?'}")
    return [Cause(f"Der Mailserver {host} antwortet nicht; {waiting} Nachrichten warten.", "S-9")]


def _model_ready(details: dict[str, Any]) -> list[Cause]:
    model = _shown(details.get("model") or details.get("alias") or "?")
    return [Cause(f"Das Modell {model} ist nicht geladen; Anfragen schlagen fehl.", "S-2")]


def _halt(details: dict[str, Any]) -> list[Cause]:
    if details.get("problem"):
        return [Cause(
            "Die Not-Aus-Datei ist nicht lesbar; alle Module gelten als per Not-Aus abgeschaltet.",
            "S-5",
        )]
    by = _shown(details.get("by") or "unbekannt")
    since = details.get("since")
    return [Cause(
        f"Die Plattform ist per Not-Aus abgeschaltet (gesetzt von {by} um "
        f"{_time(since if isinstance(since, int) else None)}).",
        "S-5",
    )]


def scope_module(scope: str) -> str:
    """The module an exchange scope opens (its audience), as the sentence names it."""
    audience = kit_names.exchange_audience(scope)
    return module_name(audience) if audience else "das Modul"


def _realm(details: dict[str, Any]) -> list[Cause]:
    causes = []
    for line in details.get("deviations") or []:
        found = _MISSING_SCOPE.match(str(line))
        if found:
            client, scope = _shown(found["client"]), _shown(found["scope"])
            causes.append(Cause(
                f"Dem Client {client} fehlt der Scope {scope}; Zugriffe auf "
                f"{scope_module(scope)} werden abgelehnt.",
                "S-6",
            ))
    return causes


_BY_CHECK = {
    "disk_space": _disk,
    "certs": _certs,
    "smtp": _smtp,
    "model_ready": _model_ready,
    "halt": _halt,
    "realm": _realm,
}
# Checks whose failure is a container that does not run: their sentence comes from the
# container states, so both rows name the same cause.
_FROM_CONTAINERS = {"container_health": None, "model_gateway": "S-1"}


def general(name: str) -> Cause:
    return Cause(
        f"Die Prüfung „{_shown(name)}“ meldet einen Fehler; die Zeile darüber nennt die Werte.",
        None,
    )


def explain(
    checks: Iterable[Any], report: status.StatusReport | None
) -> dict[str, list[Cause]]:
    """{check name: causes} for every failing check; a failing check always has one."""
    from_containers = container_causes(report)
    out: dict[str, list[Cause]] = {}
    for check in checks:
        if check.status != "fail":
            continue
        details = check.details if isinstance(check.details, dict) else {}
        causes: list[Cause] = []
        if check.name in _BY_CHECK:
            causes = _BY_CHECK[check.name](details)
        elif check.name in _FROM_CONTAINERS:
            section = _FROM_CONTAINERS[check.name]
            causes = [c for c in from_containers if section is None or c.section == section]
            if not causes and section == "S-1":
                causes = [Cause(
                    "Das Modell-Gateway (LiteLLM) antwortet nicht; Module können keine "
                    "Modelle nutzen.",
                    "S-1",
                )]
        out[check.name] = causes or [general(check.name)]
    return out


def format_lines(causes: Sequence[Cause]) -> list[str]:
    return [f"    -> {cause.line()}" for cause in causes]
