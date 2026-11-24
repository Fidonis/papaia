"""The core start gate on the operator's side (sicherheit §4.9 (2a); docs/lifecycle.md).

papaia-lifecycle keeps the edge closed after every start until its state is not older
than the erasure journal at the backup target. This module holds what papaia-ctl adds:

- `papaia-ctl startgate open --unverified --reason=<text> --requested-by=<sub>
  --confirmed-by=<sub>` opens a gate held closed by an unreachable backup target (not
  one held closed by a failed replay: its backlog is still due). Both persons hold
  `papaia-admin` and are active; the confirming person signed in within the last 300 s.
  Two different persons are needed unless the four-eyes rule is off, and never only one
  in the profile `kritis` (E-18). The check runs against the
  realm with the admin account of papaia-ctl; papaia-lifecycle records the override,
  writes the audit row `startgate_override` and mails the operations address. A refusal
  is one audit row as well. The confirming person signs in over the administration
  path: the proxy admin host, whose sign-in at the identity provider passes the closed
  gate.
- `papaia-ctl startgate acknowledge --reason=<text> --by=<sub>`: an administrator,
  freshly signed in, reviewed an override whose persons a later journal entry locked;
  `doctor startgate` no longer fails for it.
- `doctor startgate`: the gate from papaia-lifecycle's health report, as the pattern-8
  messages of betrieb BE-16a Nr. 2a.
- the edge: one managed block in the proxy's `server_proxy.conf`, which the proxy
  manager includes in every proxy host. It names each public host by its gate key and
  asks the check service (`auth_request`) for every request; a closed gate, an expired
  lease or a check service that does not answer shows the maintenance page (503).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable

from . import realm_sync as rs

LIFECYCLE_SERVICE = "papaia-lifecycle"
CHECK_SERVICE = "papaia-startgate-check"
CHECK_PORT = 8080
ADMIN_ROLE = "papaia-admin"
FRESH_LOGIN_SECONDS = 300
WRITER = "papaia-ctl/startgate"
GATE_STATUSES = ("checking", "open", "behind", "unverified", "replay_failed", "override")
PROFILES = ("standard", "kritis")
_SUB_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_REASON_RE = re.compile(r"^[^\x00-\x1f\x7f-\x9f]{1,500}$")
_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$"
)
_CONTACT_MAX = 200

# Pattern 8 (betrieb BE-16a Nr. 2a): what happened and what follows; one action; the id.
MESSAGES = {
    "CORE-STARTGATE-CHECK": (
        "Die Plattform prüft nach einem Neustart ihren Datenstand und ist kurz nicht "
        "erreichbar. Es wurde nichts ausgeführt.",
        "Versuchen Sie es in einigen Minuten erneut.",
    ),
    "CORE-STARTGATE-BEHIND": (
        "Der Datenstand ist älter als das Löschjournal; Kontosperren und Löschungen werden "
        "nachgespielt, die Plattform bleibt bis dahin geschlossen.",
        "Warten Sie das Ende ab; die Plattform öffnet danach selbst (siehe Handbuch §S-10).",
    ),
    "CORE-STARTGATE-UNVERIFIED": (
        "Das Löschjournal am Sicherungsziel ist nicht erreichbar; die Plattform bleibt "
        "geschlossen.",
        "Stellen Sie die Verbindung zum Sicherungsziel wieder her (siehe Handbuch §S-10).",
    ),
    "CORE-STARTGATE-REPLAY-FAILED": (
        "Das Nachspielen ist für {services} fehlgeschlagen; {services} bleibt geschlossen.",
        "Prüfen Sie {services} mit papaia-ctl doctor (siehe Handbuch §S-10).",
    ),
    "CORE-STARTGATE-OVERRIDE": (
        "Die Plattform ist ohne Prüfung gegen das Löschjournal geöffnet (Übersteuerung "
        "durch {first} und {second} um {at}).",
        "Stellen Sie die Verbindung zum Sicherungsziel wieder her; die Prüfung läuft jede Minute.",
    ),
    "CORE-STARTGATE-CREDENTIAL-REPLAY": (
        "Die Konten {subs} sind deaktiviert, weil ihre Zugangsdaten nach dem Sicherungsstand "
        "geändert wurden.",
        "Setzen Sie für diese Konten die Zugangsdaten neu und aktivieren Sie sie (siehe "
        "Handbuch §S-10).",
    ),
    "CORE-STARTGATE-ROLE-REPLAY": (
        "Die Konten {subs} sind deaktiviert, weil ihnen nach dem Sicherungsstand eine Rolle "
        "entzogen wurde, die das Löschjournal nicht benennt.",
        "Prüfen Sie die Rollen dieser Konten und aktivieren Sie sie (siehe Handbuch §S-10).",
    ),
    "CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR": (
        "Die Übersteuerung wurde von {person} bestätigt, deren Konto danach gesperrt oder "
        "geändert wurde.",
        "Prüfen Sie die Übersteuerung mit der zweiten Person und bestätigen Sie die Prüfung "
        "mit papaia-ctl startgate acknowledge (siehe Handbuch §S-10).",
    ),
    "CORE-STARTGATE-OVERRIDE-DENIED": (
        "Die Übersteuerung wurde nicht ausgeführt; sie braucht eine zweite Person mit "
        "papaia-admin.",
        "Lassen Sie die Übersteuerung von einer zweiten Person im Verwaltungsweg bestätigen.",
    ),
}


GATE_ADMIN_KEY = "admin"


def is_gate_key(value: object) -> bool:
    return isinstance(value, str) and bool(_KEY_RE.match(value))


class StartgateError(ValueError):
    """Input papaia-ctl refuses before it asks anyone."""


def message(code: str, correlation: str, **values: str) -> str:
    first, second = MESSAGES[code]
    return f"{first.format(**values)} {second.format(**values)} Kennung: {code} {correlation}"


def check_reason(reason: object) -> str:
    if not isinstance(reason, str) or not _REASON_RE.match(reason):
        raise StartgateError("--reason must be 1 to 500 characters on one line")
    return reason


def _check_sub(value: object, flag: str) -> str:
    if not isinstance(value, str) or not _SUB_RE.match(value):
        raise StartgateError(f"{flag} must be the account id (sub) of a person")
    return value


# ─────────────────────────────────────────────────────────────────────────
# the override
# ─────────────────────────────────────────────────────────────────────────


EXEC_COMMANDS = ("startgate-override", "startgate-acknowledge")
_OVERRIDE = "startgate_override"
_ACKNOWLEDGE = "startgate_override_acknowledged"


def _refused(operation: str) -> rs.Change:
    return rs.Change("startgate", "startgate.json", "refused", operation, "operation")


def _denied(audit, cid: str, code: str, detail: dict, operation: str = _OVERRIDE) -> int:
    audit.write(_refused(operation), "denied", code, host=True, detail=detail)
    if operation == _OVERRIDE:
        print(message("CORE-STARTGATE-OVERRIDE-DENIED", cid), file=sys.stderr, flush=True)
    else:
        print(f"Refused ({code}). Kennung: {cid}", file=sys.stderr, flush=True)
    return 2


def _keycloak_error(audit, detail: dict, operation: str) -> int:
    """Keycloak failed after the person was found: one audit row, exit 1."""
    audit.write(_refused(operation), "error", "keycloak_error", host=True, detail=detail)
    print("Keycloak not reachable: the check of the person failed", file=sys.stderr, flush=True)
    return 1


def _problem(call, sub: str, now: int, *, fresh: bool) -> str | None:
    """_person_problem, with a Keycloak failure after the user lookup as `keycloak_error`."""
    try:
        return _person_problem(call, sub, now, fresh=fresh)
    except rs.RealmSyncError:
        return "keycloak_error"


def _person_problem(call, sub: str, now: int, *, fresh: bool) -> str | None:
    """Why `sub` cannot take part in the override, or None."""
    try:
        user = call("GET", f"/users/{sub}")
    except rs.RealmSyncError:
        return "unknown_account"
    if not isinstance(user, dict) or user.get("enabled") is not True:
        return "account_disabled"
    roles = call("GET", f"/users/{sub}/role-mappings/realm/composite") or []
    if ADMIN_ROLE not in {r.get("name") for r in roles if isinstance(r, dict)}:
        return "no_admin_role"
    if fresh:
        query = urllib.parse.urlencode({"user": sub, "type": "LOGIN", "max": "1"})
        logins = call("GET", f"/events?{query}") or []
        when = logins[0].get("time") if logins and isinstance(logins[0], dict) else None
        if (
            not isinstance(when, int)
            or isinstance(when, bool)
            or now - when // 1000 > FRESH_LOGIN_SECONDS
        ):
            return "no_fresh_login"
    return None


def open_unverified(
    call: Callable,
    run: Callable[[list[str]], subprocess.CompletedProcess],
    audit,
    *,
    reason: str,
    requested_by: str,
    confirmed_by: str,
    four_eyes: str,
    profile: str,
    now: int | None = None,
) -> int:
    """Check both persons in the realm, then hand the override to papaia-lifecycle
    (`run` executes its command in the running container). 0 recorded, 2 refused."""
    check_reason(reason)
    _check_sub(requested_by, "--requested-by")
    _check_sub(confirmed_by, "--confirmed-by")
    if four_eyes not in ("on", "off"):
        raise StartgateError("the four-eyes setting must be on or off")
    if profile not in PROFILES:
        raise StartgateError("the security profile must be standard or kritis")
    now = int(time.time()) if now is None else now
    cid = rs.new_correlation_id()
    single = requested_by == confirmed_by
    detail = {"requested_by": requested_by, "confirmed_by": confirmed_by}
    if single and (four_eyes == "on" or profile == "kritis"):
        return _denied(audit, cid, "four_eyes", detail)
    for sub, fresh in ((requested_by, single), (confirmed_by, True)):
        problem = _problem(call, sub, now, fresh=fresh)
        if problem == "keycloak_error":
            return _keycloak_error(audit, {**detail, "person": sub}, _OVERRIDE)
        if problem is not None:
            return _denied(audit, cid, problem, {**detail, "person": sub})
    args = [
        "startgate-override",
        f"--reason={reason}",
        f"--requested-by={requested_by}",
        f"--confirmed-by={confirmed_by}",
    ]
    if single:
        args.append("--single-person")
    done = run(args)
    change = rs.Change("startgate", "startgate.json", "opened", "startgate_override", "operation")
    if done.returncode != 0:
        audit.write(change, "error", "lifecycle_refused", host=True, detail=detail)
        print(
            "papaia-lifecycle did not apply the override: the gate is not held closed by an "
            "unreachable backup target, or the service does not run "
            "('papaia-ctl doctor startgate').",
            file=sys.stderr,
            flush=True,
        )
        return 2
    audit.write(change, "allowed", host=True, detail={**detail, "single_person": single})
    print("Override applied; papaia-lifecycle checks again every minute.", flush=True)
    return 0


def acknowledge(
    call: Callable,
    run: Callable[[list[str]], subprocess.CompletedProcess],
    audit,
    *,
    reason: str,
    by: str,
    now: int | None = None,
) -> int:
    """`papaia-ctl startgate acknowledge`: `by` (papaia-admin, active, signed in within
    300 s) reviewed an override of persons locked afterwards. papaia-lifecycle refuses
    when nothing is to acknowledge or `by` is one of those persons. 0 applied, 1
    Keycloak failed, 2 refused."""
    check_reason(reason)
    _check_sub(by, "--by")
    now = int(time.time()) if now is None else now
    cid = rs.new_correlation_id()
    detail = {"by": by}
    problem = _problem(call, by, now, fresh=True)
    if problem == "keycloak_error":
        return _keycloak_error(audit, detail, _ACKNOWLEDGE)
    if problem is not None:
        return _denied(audit, cid, problem, detail, _ACKNOWLEDGE)
    done = run(["startgate-acknowledge", f"--reason={reason}", f"--by={by}"])
    change = rs.Change("startgate", "startgate.json", "acknowledged", _ACKNOWLEDGE, "operation")
    if done.returncode != 0:
        audit.write(change, "error", "lifecycle_refused", host=True, detail=detail)
        print(
            "papaia-lifecycle did not apply the acknowledgement: no override of a person "
            "locked afterwards is open, the person is one of them, or the service does not "
            "run ('papaia-ctl doctor startgate').",
            file=sys.stderr,
            flush=True,
        )
        return 2
    audit.write(change, "allowed", host=True, detail=detail)
    print("Acknowledged; 'papaia-ctl doctor startgate' no longer lists the override.", flush=True)
    return 0


_EXEC_FLAGS = {
    "startgate-override": {
        "--reason": "reason", "--requested-by": "requested_by", "--confirmed-by": "confirmed_by",
    },
    "startgate-acknowledge": {"--reason": "reason", "--by": "by"},
}  # fmt: skip


def _exec_request(args: list[str]) -> str:
    """The stdin of `lifecycle.py startgate-override` or `startgate-acknowledge` for the
    arguments open_unverified or acknowledge build."""
    if not args or args[0] not in EXEC_COMMANDS:
        raise StartgateError("not a start gate request")
    command, flags = args[0], _EXEC_FLAGS[args[0]]
    values: dict = {"single_person": False} if command == "startgate-override" else {}
    for arg in args[1:]:
        if arg == "--single-person" and command == "startgate-override":
            values["single_person"] = True
            continue
        name, sep, value = arg.partition("=")
        key = flags.get(name)
        if not sep or key is None or key in values:
            raise StartgateError(f"unexpected argument {name!r}")
        values[key] = value
    check_reason(values.get("reason"))
    for flag, key in flags.items():
        if key != "reason":
            _check_sub(values.get(key), flag)
    return json.dumps(values, ensure_ascii=True)


def lifecycle_runner(project: str) -> Callable[[list[str]], subprocess.CompletedProcess]:
    """`docker exec` into the running papaia-lifecycle of Compose project `project`. The
    command is fixed; the request (`args` as open_unverified builds them) passes as one
    JSON object on stdin, so nothing typed becomes part of a command line."""

    def run(args: list[str]) -> subprocess.CompletedProcess:
        request = _exec_request(args)
        command = EXEC_COMMANDS[EXEC_COMMANDS.index(args[0])]
        found = subprocess.run(
            [
                "docker", "ps", "-q",
                "--filter", f"label=com.docker.compose.project={project}",
                "--filter", f"label=com.docker.compose.service={LIFECYCLE_SERVICE}",
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
        ids = found.stdout.split()
        if found.returncode != 0 or len(ids) != 1:
            return subprocess.CompletedProcess(args, 1, "", "papaia-lifecycle does not run")
        return subprocess.run(
            [
                "docker", "exec", "-i", ids[0], "python3", "-I",
                "/opt/papaia-lifecycle/lifecycle.py", command,
                "--key-dir=/var/lib/papaia-lifecycle",
            ],
            input=request, capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip

    return run


# ─────────────────────────────────────────────────────────────────────────
# doctor startgate
# ─────────────────────────────────────────────────────────────────────────


def _subs(gate: dict, key: str) -> list[str]:
    value = gate[key]
    if not isinstance(value, list) or not all(
        isinstance(s, str) and _SUB_RE.match(s) for s in value
    ):
        raise ValueError(key)
    return value


def doctor_result(gate: object) -> tuple[str, str]:
    """(pass|warn|fail, text) for the `startgate` block of the health report; ValueError
    when the block is not one."""
    from . import doctor

    if not isinstance(gate, dict) or gate.get("status") not in GATE_STATUSES:
        raise ValueError("status")
    cid = gate.get("correlation_id")
    if not isinstance(cid, str) or not _SUB_RE.match(cid):
        raise ValueError("correlation_id")
    failed = gate.get("failed")
    if not isinstance(failed, list) or not all(
        isinstance(k, str) and _KEY_RE.match(k) for k in failed
    ):
        raise ValueError("failed")
    for key in ("credential_replay", "role_replay", "revoked_actors"):
        if key not in gate:
            raise ValueError(key)
    revoked, credentials, roles = (
        _subs(gate, "revoked_actors"),
        _subs(gate, "credential_replay"),
        _subs(gate, "role_replay"),
    )
    fails: list[str] = []
    warns: list[str] = []
    status = gate["status"]
    if status == "checking":
        fails.append(message("CORE-STARTGATE-CHECK", cid))
    elif status == "behind":
        fails.append(message("CORE-STARTGATE-BEHIND", cid))
    elif status == "unverified":
        fails.append(message("CORE-STARTGATE-UNVERIFIED", cid))
    elif status == "replay_failed":
        fails.append(message("CORE-STARTGATE-REPLAY-FAILED", cid, services=", ".join(failed)))
    elif status == "override":
        override = gate.get("override")
        if not isinstance(override, dict):
            raise ValueError("override")
        at = override.get("at")
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(at)) if isinstance(at, int) else "?"
        warns.append(
            message(
                "CORE-STARTGATE-OVERRIDE",
                cid,
                first=str(override.get("requested_by")),
                second=str(override.get("confirmed_by")),
                at=when,
            )  # fmt: skip
        )
    for sub in revoked:
        fails.append(message("CORE-STARTGATE-OVERRIDE-REVOKED-ACTOR", cid, person=sub))
    if credentials:
        warns.append(message("CORE-STARTGATE-CREDENTIAL-REPLAY", cid, subs=", ".join(credentials)))
    if roles:
        warns.append(message("CORE-STARTGATE-ROLE-REPLAY", cid, subs=", ".join(roles)))
    if fails:
        return doctor.FAIL, " ".join(fails + warns)
    if warns:
        return doctor.WARN, " ".join(warns)
    return doctor.PASS, "the start gate is open; the state is not older than the erasure journal"


# ─────────────────────────────────────────────────────────────────────────
# the edge
# ─────────────────────────────────────────────────────────────────────────

_BLOCK_BEGIN = "# >>> papaia: core start gate (managed by papaia-ctl, do not edit)"
_BLOCK_END = "# <<< papaia start gate"
BLOCK_BEGIN = _BLOCK_BEGIN
BLOCK_END = _BLOCK_END


def _contact_header(contact: str | None) -> str | None:
    """The contact point as a header value: percent-encoded, so no quote, `$`, `;` or
    line break reaches the proxy configuration; the check service decodes it."""
    if not contact:
        return None
    return urllib.parse.quote(contact[:_CONTACT_MAX], safe="-._~ ").replace(" ", "%20")


def edge_block(host_keys: dict[str, str], *, contact: str | None) -> str:
    """The managed block for `server_proxy.conf`: every request of a proxy host goes
    through the check service first; host names map to gate keys (`core` otherwise)."""
    lines = [
        _BLOCK_BEGIN,
        'set $papaia_gate_service "core";',
    ]
    for host, key in sorted(host_keys.items()):
        if not isinstance(host, str) or not _HOST_RE.match(host):
            raise StartgateError(f"{host!r} is not a host name the gate can name")
        if not isinstance(key, str) or not _KEY_RE.match(key):
            raise StartgateError(f"{key!r} is not a gate key")
        lines.append(f'if ($host = "{host}") {{ set $papaia_gate_service "{key}"; }}')
    header = _contact_header(contact)
    contact_line = f'proxy_set_header X-Papaia-Gate-Contact "{header}";' if header else ""
    # Resolved per request: the proxy starts and reloads also while the check service
    # does not run, and every request then shows the maintenance page.
    upstream = f"http://{CHECK_SERVICE}:{CHECK_PORT}"
    lines += [
        "resolver 127.0.0.11 valid=10s ipv6=off;",
        f'set $papaia_gate_upstream "{upstream}";',
        "auth_request /.papaia-startgate;",
        "error_page 401 500 502 503 504 = @papaia_startgate;",
        "location = /.papaia-startgate {",
        "    internal;",
        "    auth_request off;",
        "    proxy_pass $papaia_gate_upstream/check;",
        "    proxy_pass_request_body off;",
        '    proxy_set_header Content-Length "";',
        "    proxy_set_header X-Papaia-Gate-Service $papaia_gate_service;",
        # The administrators' sign-in at the identity provider passes a closed gate;
        # the check service matches the original URI.
        "    proxy_set_header X-Papaia-Gate-Uri $request_uri;",
        "    proxy_connect_timeout 2s;",
        "    proxy_read_timeout 2s;",
        "}",
        "location @papaia_startgate {",
        "    auth_request off;",
        "    rewrite ^ /maintenance break;",
        "    proxy_pass $papaia_gate_upstream;",
        "    proxy_method GET;",
        "    proxy_pass_request_body off;",
        '    proxy_set_header Content-Length "";',
        *([f"    {contact_line}"] if contact_line else []),
        "    proxy_intercept_errors off;",
        "}",
        _BLOCK_END,
    ]
    return "\n".join(lines) + "\n"


def strip_block(current: str) -> str:
    """`current` without the managed start gate block."""
    begin = current.find(_BLOCK_BEGIN)
    if begin < 0:
        return current
    end = current.find(_BLOCK_END + "\n", begin)
    if end < 0:
        return current[:begin]
    return current[:begin] + current[end + len(_BLOCK_END) + 1 :]


# ─────────────────────────────────────────────────────────────────────────
# the shell command
# ─────────────────────────────────────────────────────────────────────────


def main(
    tree: dict,
    config_dir,
    *,
    reason: str,
    requested_by: str = "",
    confirmed_by: str = "",
    action: str = "open",
    by: str = "",
) -> int:
    """`papaia-ctl startgate open --unverified` or `startgate acknowledge`; 0 applied,
    1 Keycloak not reachable, 2 refused."""
    from pathlib import Path

    from . import catalog, security_profile, service_accounts
    from . import keycloak_role_sync as kcs

    config_dir = Path(config_dir)
    root = tree.get("", {})
    try:
        if action not in ("open", "acknowledge"):
            raise StartgateError("the action must be open or acknowledge")
        check_reason(reason)
        if action == "acknowledge":
            _check_sub(by, "--by")
        else:
            _check_sub(requested_by, "--requested-by")
            _check_sub(confirmed_by, "--confirmed-by")
        profile = security_profile.name_of(root)
        four_eyes = catalog.four_eyes_in_effect(profile, catalog.stored_four_eyes(config_dir))
        base_url, ctx, admin_password, _ = service_accounts._connection(tree, config_dir)
    except (StartgateError, security_profile.ProfileError, catalog.CatalogError) as exc:
        print(f"Refused: {exc}", file=sys.stderr, flush=True)
        return 2
    except service_accounts.RotationError as exc:
        print(f"Refused: {exc}", file=sys.stderr, flush=True)
        return 2
    project = root.get("COMPOSE_PROJECT_NAME") or "papaia"
    try:
        kcs._wait_for_keycloak(base_url, ctx)
        call = rs.MasterAdmin(base_url, ctx, admin_password).call
        with rs.AuditLog(
            rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER
        ) as audit:
            if action == "acknowledge":
                return acknowledge(
                    call, lifecycle_runner(project), audit, reason=reason, by=by
                )
            return open_unverified(
                call, lifecycle_runner(project), audit,
                reason=reason, requested_by=requested_by, confirmed_by=confirmed_by,
                four_eyes=four_eyes, profile=profile,
            )  # fmt: skip
    except (TimeoutError, OSError, rs.RealmSyncError) as exc:
        print(f"Keycloak not reachable: {type(exc).__name__}", file=sys.stderr, flush=True)
        return 1
