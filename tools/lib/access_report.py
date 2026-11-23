"""`papaia-ctl report permissions` and `report confirm`, and the inputs file of the
permission report (security 1.16, OPS-19; docs/permission-report.md).

papaia-audit builds the report itself (src/infra/audit/papaia_audit/report.py), reading
the realm as the service account `svc-papaia-audit-report` (`view-users` only) and the
inputs file this module writes. `papaia-ctl report permissions` only calls the route
`POST /v1/access-reports/build` of papaia-audit inside its container (`docker exec`, like
`audit verify`) with the person's token and prints the answer byte for byte; it reads
nothing from the realm and needs no master admin. papaia-audit checks the role
`papaia-auditor` and records every retrieval, also a refused one.

`papaia-ctl report confirm` records a confirmation (role `papaia-admin`, never for one's
own row) the same way.

The token is read from a file or stdin (`--token-file=PATH|-`), never from the command
line, and never printed.

The inputs file `$PAPAIA_CONFIG_DIR/infra/audit/service/access-report-inputs.json`
(format `papaia.access-report-inputs/1`, tools/schemas/access-report-inputs.schema.json)
is written on every `realm sync`, which `start` runs, with the master admin the sync
holds anyway: the managed module clients (uuid, client id), the declared service accounts
with owner, deputy and audience, the confirmed exchange-right pairings and the platform
pairings of the realm sync, the ids of the emergency account, the delegation lifetime,
the offline-session limits of the realm and the recertification period. It holds no
secret and no credential; papaia-audit sees it read-only.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TextIO

from . import audit, common, kit_names
from . import realm_sync as rs

FORMAT = "papaia.access-report/1"
INPUTS_FORMAT = "papaia.access-report-inputs/1"
INPUTS_FILE = "access-report-inputs.json"
KEYCLOAK_CA_FILE = "keycloak-ca.crt"
KINDS = ("person", "system")
FORMATS = ("json", "csv")
PERIOD_KEY = "PAPAIA_RECERTIFICATION_DAYS"
PERIOD_DEFAULT, PERIOD_MIN, PERIOD_MAX = 180, 30, 730
BUILD_PATH = "/v1/access-reports/build"
CONFIRM_PATH = "/v1/access-reports/confirmations"
MAX_TOKEN_BYTES = 8192
EXEC_TIMEOUT_SECONDS = 120.0
# Exit status of a refused call (401/403): nothing is shown.
REFUSED = 3

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Same names as papaia-audit accepts: valid object_ref ids of the audit schema (no '|').
_KEY_RE = re.compile(r"^(person|system):[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}$")
_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_PERIOD_RE = re.compile(r"^[0-9]{1,4}$")

# (status, content type, body text) of one call into papaia-audit.
Gate = Callable[[str, str, dict], tuple[int, str, str]]


class ReportError(Exception):
    """The call cannot be made; the message says why (no token)."""


class AuditUnavailable(ReportError):
    """papaia-audit is not running or did not answer (exit status 1, not invalid input)."""


def period_days(env: dict[str, str]) -> int:
    value = env.get(PERIOD_KEY)
    if value is None or value == "":
        return PERIOD_DEFAULT
    if not _PERIOD_RE.match(value) or not PERIOD_MIN <= int(value) <= PERIOD_MAX:
        raise ReportError(f"{PERIOD_KEY} must be {PERIOD_MIN} to {PERIOD_MAX} days")
    return int(value)


# ─────────────────────────────────────────────────────────────────────────
# the inputs file (written by realm sync)
# ─────────────────────────────────────────────────────────────────────────


def inputs_path(config_dir: Path) -> Path:
    return audit.audit_dir(config_dir) / "service" / INPUTS_FILE


def _module_clients(clients: Iterable[dict]) -> list[dict]:
    """The managed clients persons sign in to (delegations live there)."""
    found = []
    for client in clients:
        attributes = client.get("attributes") or {}
        if attributes.get(rs.MANAGED) != "true" or attributes.get(rs.KIND) == rs.SERVICE_ACCOUNT:
            continue
        if _ID_RE.match(str(client.get("id", ""))) and isinstance(client.get("clientId"), str):
            found.append({"id": client["id"], "client_id": client["clientId"]})
    return sorted(found, key=lambda c: c["client_id"])


def _service_accounts(clients: Iterable[dict]) -> list[dict]:
    """The declared service accounts with owner, deputy, audience and effects, from the
    attributes the realm sync keeps on their clients (no secret, no key)."""
    rows = []
    for client in clients:
        attributes = client.get("attributes") or {}
        if attributes.get(rs.MANAGED) != "true" or attributes.get(rs.KIND) != rs.SERVICE_ACCOUNT:
            continue
        rows.append(
            {
                "id": client["clientId"],
                "module": attributes.get(rs.OWNER),
                "owner_sub": attributes.get("papaia.owner_sub"),
                "deputy_sub": attributes.get("papaia.deputy_sub"),
                "audiences": sorted(
                    audience
                    for s in client.get("optionalClientScopes") or []
                    if (audience := kit_names.exchange_audience(s)) is not None
                ),
                "effects": sorted(
                    e for e in (attributes.get("papaia.effects") or "").split(",") if e
                ),
            }
        )
    return sorted(rows, key=lambda a: a["id"])


def _pairings(pairings: Iterable[rs.Pairing]) -> list[dict]:
    rows = []
    for pairing in pairings:
        if not pairing.confirmed:
            continue  # waiting for a second person: no right yet
        rows.append(
            {
                "client": pairing.client,
                "audience": pairing.audience,
                "effects": [e for e in rs.EFFECTS if e in pairing.effects],
                "requested_by": pairing.requested_by,
                "confirmed_by": pairing.confirmed_by,
            }
        )
    return sorted(rows, key=lambda p: (p["audience"], p["client"]))


def build_inputs(
    call,
    *,
    pairings: Iterable[rs.Pairing],
    delegations: dict,
    breakglass_ids: frozenset[str],
    period: int,
    now: float | None = None,
) -> dict:
    """The inputs document; `call` is the master admin's Admin API call (GET only)."""
    from . import realm_hardening  # it imports delegation_lifetime, which imports kcs

    clients = call("GET", "/clients") or []
    return {
        "format": INPUTS_FORMAT,
        "written_at": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now)
        ),
        "module_clients": _module_clients(clients),
        "service_accounts": _service_accounts(clients),
        "pairings": _pairings(pairings),
        "breakglass_ids": sorted(breakglass_ids),
        "sessions": {
            "offline": realm_hardening.offline_limits(call("GET", "") or {}),
            "delegations": dict(delegations),
        },
        "recertification_days": period,
    }


def write_inputs(config_dir: Path, document: dict) -> Path:
    """Write the inputs file atomically; readable by papaia-audit (no secret in it).
    Next to it a copy of the local CA certificate (public), with which papaia-audit
    checks Keycloak's certificate; the CA key stays where it is."""
    path = inputs_path(config_dir)
    common.atomic_write(path, json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o644)
    ca = Path(config_dir) / "certs" / "local-ca.crt"
    if ca.is_file() and not ca.is_symlink():
        target = path.with_name(KEYCLOAK_CA_FILE)
        common.atomic_write(target, ca.read_text(encoding="ascii"))
        os.chmod(target, 0o644)
    return path


# ─────────────────────────────────────────────────────────────────────────
# calls into papaia-audit
# ─────────────────────────────────────────────────────────────────────────


def read_token(source: str, *, stdin: TextIO | None = None) -> str:
    """The person's bearer token from a file, or `-` for stdin."""
    try:
        if source == "-":
            text = (stdin or sys.stdin).read(MAX_TOKEN_BYTES + 2)
        else:
            with open(source, encoding="ascii") as fh:
                text = fh.read(MAX_TOKEN_BYTES + 2)
    except (OSError, UnicodeDecodeError) as exc:
        raise ReportError(f"the token cannot be read ({type(exc).__name__})") from None
    token = text.strip()
    if not token or len(token) > MAX_TOKEN_BYTES or not _TOKEN_RE.match(token):
        raise ReportError("the token file does not hold one bearer token")
    return token


def service_gate(config_dir: Path) -> Gate:
    """The route call inside the running papaia-audit (`python -m papaia_audit access`):
    the request, with the token, goes on stdin; the answer is one JSON object with the
    status, the content type and the body as the route sent it."""

    def gate(path: str, token: str, body: dict) -> tuple[int, str, str]:
        try:
            container = audit.find_container(config_dir)
        except audit.AuditError as exc:
            raise AuditUnavailable(str(exc)) from None
        argv = ["docker", "exec", "-i", container, "python3", "-I", "-m", "papaia_audit", "access"]
        request = {
            "method": "POST",
            "path": path,
            "authorization": f"Bearer {token}",
            "body": body,
        }
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                input=json.dumps(request),
                text=True,
                capture_output=True,
                timeout=EXEC_TIMEOUT_SECONDS,
                check=False,
            )
            answer = json.loads(done.stdout) if done.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, ValueError):
            answer = None
        if (
            not isinstance(answer, dict)
            or type(answer.get("status")) is not int
            or not isinstance(answer.get("content_type"), str)
            or not isinstance(answer.get("text"), str)
        ):
            raise AuditUnavailable("papaia-audit did not answer; is the stack running?")
        return answer["status"], answer["content_type"], answer["text"]

    return gate


def _json_body(content_type: str, text: str) -> dict:
    if "json" not in content_type:
        return {}
    try:
        body = json.loads(text)
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _refusal(status: int, body: dict, err: TextIO) -> int:
    message = body.get("message") if isinstance(body.get("message"), str) else ""
    hint = body.get("hint") if isinstance(body.get("hint"), str) else ""
    code = body.get("code") if isinstance(body.get("code"), str) else f"HTTP {status}"
    print(f"Refused by papaia-audit ({status}, {code}). {message} {hint}".rstrip(), file=err,
          flush=True)
    return REFUSED if status in (401, 403) else 1


def run(by: str, fmt: str, token: str, gate: Gate, out: TextIO, *, err=None) -> int:
    """Have papaia-audit build the report and print its answer unchanged. 0: printed,
    3: refused (no role, no valid token), 1: papaia-audit unavailable or another error."""
    if by not in KINDS:
        raise ReportError(f"unknown report '{by}' (person or system)")
    if fmt not in FORMATS:
        raise ReportError(f"unknown format '{fmt}' (json or csv)")
    status, content_type, text = gate(BUILD_PATH, token, {"by": by, "format": fmt})
    if status != 200:
        return _refusal(status, _json_body(content_type, text), err or sys.stderr)
    out.write(text)
    out.flush()
    return 0


def confirm(key: str, digest: str, token: str, gate: Gate, out: TextIO, *, err=None) -> int:
    """Record that the administration confirmed one row (`key`) with the content `digest`."""
    if not _KEY_RE.match(key):
        raise ReportError("--key must be person:<sub> or system:<audience>")
    if not _DIGEST_RE.match(digest):
        raise ReportError("--digest must be sha256:<64 hex>, the row's digest in the report")
    status, content_type, text = gate(CONFIRM_PATH, token, {"key": key, "digest": digest})
    body = _json_body(content_type, text)
    if status != 201:
        return _refusal(status, body, err or sys.stderr)
    print(f"Confirmed {key} at {body.get('confirmed_at')}.", file=out, flush=True)
    return 0
