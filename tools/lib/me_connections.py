"""Mein Bereich as a person client of the connection registry (profiles `me` and `connections`).

Me lists a person's accounts, mandates and uses at the registry and ends a mandate
(`GET /api/v1/me/accounts`, `/me/mandates`, `/me/uses`,
`DELETE /api/v1/me/mandates/{account}/{service}`), always for the person of the token. The
registry accepts such a token when its `azp` is in `CONNECTIONS_PERSON_CLIENTS`, its `aud`
is `papaia-connections`, and the caller presents a client certificate of the platform CA.
The core wires the two profiles only while both are on:

- `src/infra/me/pki.yaml` asks for a client certificate of `me-web` next to its server
  certificate while `connections` is on as well (lib/pki.py, `client.with_profiles`);
- this module writes `overrides/docker-compose.me-connections.override.yml`:
  - while both profiles run on this host, `me-web` (no other service of the profile)
    joins `papaia-connections-net`, mounts its directory of the platform PKI read-only and
    gets the paths of the CA, the certificate and the key (`ME_ENV`, listed under
    `with_profiles` in src/infra/me/service-env.json);
  - while the registry runs on this host, it gets `CONNECTIONS_PERSON_CLIENTS`: the
    operator's value from `infra/connections/.env`, with `papaia-me` added while the
    profile `me` is on for the installation and taken out while it is off;
- the exchange right itself is the pairing `papaia-me` -> `papaia-connections` with the
  effects r and d (lib/realm_sync.py `PAIRING_EFFECTS`): it comes from the bill of
  materials, waits after `pairing confirm` and is assigned only after a second person's
  `pairing approve`. Without it Me gets no token for the registry.

The file is written atomically, mode 0644, and removed when the registry does not run on
this host. Every write and every removal is one `papaia.audit/1` row without content; a run
that changes nothing writes none.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from . import common, module_tls

ME_PROFILE = "me"
CONNECTIONS_PROFILE = "connections"
CLIENT = "papaia-me"
ME_SERVICE = module_tls.ME_SERVICE
REGISTRY_SERVICE = "connections"
NETWORK = "papaia-connections-net"
VARIABLE = "CONNECTIONS_PERSON_CLIENTS"
OVERRIDE = "docker-compose.me-connections.override.yml"
OVERRIDE_REF = f"overrides/{OVERRIDE}"
WRITER = "papaia-ctl/me-connections"

TLS_DIR = module_tls.TLS_DIR
# What me-web reads to call the registry with mutual TLS. The CA is the platform CA of the
# PKI: the registry's server certificate is one of it, while SSL_CERT_FILE is the local CA
# of the identity provider.
ME_ENV = {
    "ME_CONNECTIONS_CA_FILE": f"{TLS_DIR}/ca.crt",
    "ME_CONNECTIONS_CERT_FILE": f"{TLS_DIR}/client.crt",
    "ME_CONNECTIONS_KEY_FILE": f"{TLS_DIR}/client.key",
}

MAX_CLIENTS = 32
# An OIDC client id as the registry compares it with `azp`. No `$` (Compose would read an
# interpolation), no space and no comma inside a name.
_CLIENT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class MeConnectionsError(ValueError):
    """A value the override cannot be written with; the message names it."""


def person_clients(operator: str, *, me_on: bool) -> str:
    """The operator's comma-separated list, each name once and in its order, with
    `papaia-me` while the profile `me` is on and without it while it is off."""
    names: list[str] = []
    for raw in operator.split(","):
        name = raw.strip()
        if not name:
            continue
        if not _CLIENT_RE.match(name):
            raise MeConnectionsError(
                f"{VARIABLE} in infra/connections/.env: {name[:40]!r} is not a client id "
                "(letters, digits, '.', '_', ':', '-', at most 128 characters)"
            )
        if name not in names:
            names.append(name)
    if CLIENT in names and not me_on:
        names.remove(CLIENT)
    elif me_on and CLIENT not in names:
        names.append(CLIENT)
    if len(names) > MAX_CLIENTS:
        raise MeConnectionsError(f"{VARIABLE}: at most {MAX_CLIENTS} clients")
    return ",".join(names)


def _mount() -> str:
    return f"${{PAPAIA_PKI_DIR}}/core/{ME_SERVICE}:{TLS_DIR}:ro"


def override(root: dict[str, str], connections_env: dict[str, str]) -> dict | None:
    """The override for the root `.env` `root` and the registry's own `.env`; None when
    the registry does not run on this host."""
    host = {p.strip() for p in root.get("COMPOSE_PROFILES", "").split(",") if p.strip()}
    if CONNECTIONS_PROFILE not in host:
        return None
    me_on = ME_PROFILE in common.cluster_profiles(root)
    services: dict = {}
    if ME_PROFILE in host:
        services[ME_SERVICE] = {
            "networks": [NETWORK],
            "volumes": [_mount()],
            "environment": dict(ME_ENV),
        }
    services[REGISTRY_SERVICE] = {
        "environment": {VARIABLE: person_clients(connections_env.get(VARIABLE, ""), me_on=me_on)}
    }
    return {"services": services}


def _render(doc: dict) -> bytes:
    head = (
        "# Generated by papaia-ctl (Mein Bereich and the connection registry); do not edit.\n"
        f"# {VARIABLE} of the registry is set in infra/connections/.env.\n"
    )
    return (head + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)).encode()


def generate_override(config_dir: Path) -> Path | None:
    """Write, replace or remove the override; returns its path while it exists."""
    from . import realm_sync as rs  # the realm sync imports the render path

    root = common.parse_env_file(config_dir / ".env")
    connections_env = common.parse_env_file(config_dir / "infra" / "connections" / ".env")
    doc = override(root, connections_env)
    path = config_dir / "overrides" / OVERRIDE
    target = _render(doc) if doc is not None else None
    try:
        current = path.read_bytes() if path.is_file() else None
    except OSError:
        current = b""
    if current == target:
        return path if target is not None else None
    if target is None:
        change = rs.Change("file", OVERRIDE_REF, "override removed", "override.delete",
                           effect="delete")  # fmt: skip
    else:
        change = rs.Change("file", OVERRIDE_REF, "override written", "override.write")
    with rs.AuditLog(rs.audit_path(config_dir), rs.new_correlation_id(), writer=WRITER) as audit:
        try:
            if target is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "wb") as fh:
                    os.fchmod(fh.fileno(), 0o644)
                    fh.write(target)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
        except OSError:
            audit.write(change, "error", "io", host=True)
            raise
        audit.write(change, "allowed", host=True)
    return path if target is not None else None
