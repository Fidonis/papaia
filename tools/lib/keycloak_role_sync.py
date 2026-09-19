"""Idempotent Keycloak realm-role sync for the bundled internal Keycloak.

Called by `papaia-ctl start` (via `py_cli keycloak-role-sync`) when
AUTH_PROVIDER=internal_keycloak. Keycloak's own `--import-realm` only fires
on a realm that doesn't exist yet, so an existing installation never picks up
new roles, composites or protocol mappers shipped by a newer papaia-realm.json
template on its own. This module reconciles the live realm against the
rendered template instead: additive only, it never deletes or overwrites a
role, a composite edge, a protocol mapper or a user's existing role mapping.

It also migrates every current holder of the legacy `admin` role onto the new
`papaia-admin` role, without touching `admin` itself.

Uses only Python stdlib — no third-party dependencies (same constraint as
npm_provision.py).
"""

from __future__ import annotations

import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .envtree import EnvTree

_KEYCLOAK_NODE = "infra/keycloak"
_REALM = "papaia"
_LEGACY_ADMIN_ROLE = "admin"
_MIGRATION_TARGET_ROLE = "papaia-admin"


def _compose_value(raw: str) -> str:
    """Resolve a raw .env value the way docker compose does. `parse_env_file`
    keeps a trailing ` # comment` (the shipped KC_ADMIN_PASSWORD line carries
    one), but Keycloak was started with the comment stripped, so sending the
    unresolved value as the admin password is rejected."""
    if raw.startswith(('"', "'")):
        end = raw.find(raw[0], 1)
        return raw[1:end] if end != -1 else raw
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def _error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", "replace").strip()[:300]
    except Exception:
        return exc.reason if isinstance(exc.reason, str) else ""


def _ssl_context(config_dir: Path) -> ssl.SSLContext:
    ca_file = config_dir / "certs" / "local-ca.crt"
    if ca_file.is_file():
        return ssl.create_default_context(cafile=str(ca_file))
    return ssl.create_default_context()


def _wait_for_keycloak(base_url: str, ctx: ssl.SSLContext, timeout: int = 90) -> None:
    """Poll the realm's (unauthenticated) discovery document until it answers."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            url = f"{base_url}/realms/{_REALM}/.well-known/openid-configuration"
            with urllib.request.urlopen(url, timeout=3, context=ctx):
                return
        except Exception as exc:
            last_exc = exc
            time.sleep(2)
    raise TimeoutError(
        f"Keycloak at {base_url} did not become ready within {timeout}s"
        + (f": {last_exc}" if last_exc else "")
    )


def _get_admin_token(base_url: str, ctx: ssl.SSLContext, password: str) -> str:
    """Password-grant against master/admin-cli — the same flow kcadm.sh uses."""
    payload = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": password,
        }
    ).encode()
    req = urllib.request.Request(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data=payload,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        return json.loads(resp.read())["access_token"]


def _api(
    base_url: str,
    ctx: ssl.SSLContext,
    token: str,
    method: str,
    path: str,
    body: object = None,
):
    """Call the papaia realm's Admin REST API. A 409 (already exists) is
    swallowed — every caller here already checked first, so a 409 only
    happens on a repeat run racing itself and is not an error."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{base_url}/admin/realms/{_REALM}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return None
        raise


def _sync_roles(base_url, ctx, token, realm_def: dict) -> tuple[dict[str, dict], int]:
    existing = {r["name"]: r for r in _api(base_url, ctx, token, "GET", "/roles")}
    created = 0
    for role in realm_def.get("roles", {}).get("realm", []):
        name = role["name"]
        if name in existing:
            continue
        _api(
            base_url,
            ctx,
            token,
            "POST",
            "/roles",
            {
                "name": name,
                "description": role.get("description", ""),
                "composite": role.get("composite", False),
            },
        )
        existing[name] = _api(base_url, ctx, token, "GET", f"/roles/{name}")
        created += 1
        print(f"  role created: {name}", flush=True)
    return existing, created


def _sync_composites(base_url, ctx, token, realm_def: dict) -> int:
    added = 0
    for role in realm_def.get("roles", {}).get("realm", []):
        wanted = role.get("composites", {}).get("realm", [])
        if not wanted:
            continue
        name = role["name"]
        current_reps = _api(base_url, ctx, token, "GET", f"/roles/{name}/composites") or []
        current = {c["name"] for c in current_reps}
        missing = [n for n in wanted if n not in current]
        if not missing:
            continue
        reps = [_api(base_url, ctx, token, "GET", f"/roles/{n}") for n in missing]
        _api(base_url, ctx, token, "POST", f"/roles/{name}/composites", reps)
        added += len(reps)
        print(f"  composites added to {name}: {missing}", flush=True)
    return added


def _sync_protocol_mappers(base_url, ctx, token, realm_def: dict) -> int:
    added = 0
    for client in realm_def.get("clients", []):
        client_id = client["clientId"]
        matches = _api(
            base_url, ctx, token, "GET", f"/clients?clientId={urllib.parse.quote(client_id)}"
        )
        if not matches:
            continue
        client_uuid = matches[0]["id"]
        mapper_reps = _api(
            base_url, ctx, token, "GET", f"/clients/{client_uuid}/protocol-mappers/models"
        )
        existing = {m["name"] for m in mapper_reps}
        for mapper in client.get("protocolMappers", []):
            if mapper["name"] in existing:
                continue
            _api(
                base_url,
                ctx,
                token,
                "POST",
                f"/clients/{client_uuid}/protocol-mappers/models",
                mapper,
            )
            added += 1
            print(f"  protocol mapper created on {client_id}: {mapper['name']}", flush=True)
    return added


def _migrate_legacy_admins(base_url, ctx, token, existing_roles: dict[str, dict]) -> int:
    if _LEGACY_ADMIN_ROLE not in existing_roles or _MIGRATION_TARGET_ROLE not in existing_roles:
        return 0
    members = _api(base_url, ctx, token, "GET", f"/roles/{_LEGACY_ADMIN_ROLE}/users") or []
    target_rep = existing_roles[_MIGRATION_TARGET_ROLE]
    migrated = 0
    for user in members:
        user_id = user["id"]
        current = {
            r["name"]
            for r in _api(base_url, ctx, token, "GET", f"/users/{user_id}/role-mappings/realm")
        }
        if _MIGRATION_TARGET_ROLE in current:
            continue
        _api(base_url, ctx, token, "POST", f"/users/{user_id}/role-mappings/realm", [target_rep])
        migrated += 1
        who = user.get("username", user_id)
        print(f"  migrated to {_MIGRATION_TARGET_ROLE}: {who}", flush=True)
    return migrated


def sync_roles(tree: EnvTree, config_dir: Path) -> bool:
    """Reconcile realm roles/composites/protocol-mappers and run the
    admin -> papaia-admin migration. No-op when AUTH_PROVIDER is not
    'internal_keycloak' — an external OIDC provider is the operator's own
    realm to manage. Returns False if Keycloak was not reachable; True
    otherwise (including the no-op and already-in-sync cases)."""
    root = tree.get("", {})
    if root.get("AUTH_PROVIDER", "internal_keycloak") != "internal_keycloak":
        print("Keycloak role sync skipped: AUTH_PROVIDER is not internal_keycloak.", flush=True)
        return True

    keycloak = tree.get(_KEYCLOAK_NODE, {})
    admin_password = _compose_value(keycloak.get("KC_ADMIN_PASSWORD", ""))
    if not admin_password or admin_password.startswith("GENERATE_"):
        raise RuntimeError(
            f"KC_ADMIN_PASSWORD is not set in {_KEYCLOAK_NODE}/.env. Run 'papaia-ctl setup' first."
        )

    realm_json_path = config_dir / "infra" / "keycloak" / "realm-import" / "papaia-realm.json"
    if not realm_json_path.is_file():
        print(
            "Keycloak role sync skipped: no rendered realm-import file found.",
            file=sys.stderr,
            flush=True,
        )
        return False
    realm_def = json.loads(realm_json_path.read_text(encoding="utf-8"))

    port = root.get("KEYCLOAK_EXT_PORT", "8110")
    base_url = f"https://localhost:{port}"
    ctx = _ssl_context(config_dir)

    print("Waiting for Keycloak to become ready...", flush=True)
    try:
        _wait_for_keycloak(base_url, ctx)
    except TimeoutError as exc:
        print(f"Keycloak role sync skipped: {exc}", file=sys.stderr, flush=True)
        return False

    try:
        token = _get_admin_token(base_url, ctx, admin_password)
    except urllib.error.HTTPError as exc:
        print(
            f"Keycloak role sync skipped: admin login failed (HTTP {exc.code}: "
            f"{_error_detail(exc)}). KC_ADMIN_PASSWORD in {_KEYCLOAK_NODE}/.env is only "
            "used on Keycloak's first start — if the admin password was changed "
            "since, update it there.",
            file=sys.stderr,
            flush=True,
        )
        return False

    try:
        existing_roles, roles_created = _sync_roles(base_url, ctx, token, realm_def)
        composites_added = _sync_composites(base_url, ctx, token, realm_def)
        mappers_added = _sync_protocol_mappers(base_url, ctx, token, realm_def)
        migrated = _migrate_legacy_admins(base_url, ctx, token, existing_roles)
    except urllib.error.HTTPError as exc:
        print(
            f"Keycloak role sync failed: HTTP {exc.code} on {exc.url}: {_error_detail(exc)}",
            file=sys.stderr,
            flush=True,
        )
        return False
    except OSError as exc:
        print(f"Keycloak role sync failed: {exc}", file=sys.stderr, flush=True)
        return False

    print(
        f"Keycloak role sync complete: {roles_created} role(s) created, "
        f"{composites_added} composite edge(s) added, {mappers_added} protocol "
        f"mapper(s) created, {migrated} user(s) migrated to {_MIGRATION_TARGET_ROLE}.",
        flush=True,
    )
    return True
