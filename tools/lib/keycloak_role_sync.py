"""Idempotent Keycloak realm sync for the bundled internal Keycloak.

Called by `papaia-ctl start` (via `py_cli keycloak-role-sync`) when
AUTH_PROVIDER=internal_keycloak. Keycloak's own `--import-realm` only fires
on a realm that doesn't exist yet, so an existing installation never picks up
new roles, composites, clients or protocol mappers shipped by a newer
papaia-realm.json template on its own. This module reconciles the live realm
against the rendered template instead: additive only, it never deletes
anything and never overwrites a role, a composite edge, a protocol mapper or a
user's existing role mapping. A composite member is a realm role or a role of a
client; `papaia-admin` carries the `realm-management` roles that let it
administer the realm's accounts (the manager's Users page acts with the
signed-in account's own token), and an existing realm gets them from here.

Clients are handled only for the Compose profiles that need them
(PROFILE_CLIENTS), so an installation that never enables such a profile keeps
a realm without them. A missing client is created. For one that exists, the
secret is aligned with the rendered template and, when the template names a
login theme for it, a missing `login_theme` attribute is added; nothing else about it
is changed: the core `.env` is canonical for that secret, and a client left over
from an earlier add-on install would otherwise refuse the service that signs in
with the generated one.

The realm's mail server follows the optional `smtp` profile: while the mail relay is on
and configured, an existing realm without a mail server gets the relay (and the
reset-password link); a mail server the operator configured is never overwritten.

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

from . import common, smtp
from .envtree import EnvTree

_KEYCLOAK_NODE = "infra/keycloak"
_REALM = "papaia"
_LEGACY_ADMIN_ROLE = "admin"
_MIGRATION_TARGET_ROLE = "papaia-admin"

# Clients the realm template ships for an optional Compose profile. A fresh
# install gets them from the realm import; an existing realm gets them from
# this sync, and only once the profile is enabled.
PROFILE_CLIENTS: dict[str, tuple[str, ...]] = {
    "rag": ("mcp-qdrant", "mcp-qdrant-ingest"),
}


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


def _admin_base_url(root: dict[str, str]) -> str:
    """Where this process reaches Keycloak.

    On the host that is the published port. In a container (`papaia-manager` runs
    `start`, and with it this sync, in its own) `localhost` is the container itself, so
    the sync would wait and skip. There it takes the address the stack's own services
    use: the origin of `OIDC_TOKEN_URL` (`https://keycloak:8443`), which the local CA
    certificate covers. Without such a URL the published port is all there is."""
    local = f"https://localhost:{root.get('KEYCLOAK_EXT_PORT', '8110')}"
    if not common.in_container():
        return local
    parts = urllib.parse.urlsplit(root.get("OIDC_TOKEN_URL", "").strip())
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return local


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


def _client_uuid(base_url, ctx, token, client_id: str) -> str | None:
    path = f"/clients?clientId={urllib.parse.quote(client_id)}"
    matches = _api(base_url, ctx, token, "GET", path)
    return matches[0]["id"] if matches else None


def _client_role(base_url, ctx, token, client_uuid: str, name: str) -> dict | None:
    """One role of a client, or None when the client has no role of that name."""
    path = f"/clients/{client_uuid}/roles/{urllib.parse.quote(name, safe='')}"
    try:
        return _api(base_url, ctx, token, "GET", path)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _sync_composites(base_url, ctx, token, realm_def: dict) -> int:
    """Add the composite members the template names and a role does not have yet.

    A member is a realm role (`composites.realm`) or a role of a client
    (`composites.client`, a map of client id -> role names), which is how
    `papaia-admin` carries Keycloak's own user-administration rights. A client
    or a client role that cannot be found is a warning: the rest of the sync
    still has to run."""
    added = 0
    client_uuids: dict[str, str | None] = {}
    for role in realm_def.get("roles", {}).get("realm", []):
        composites = role.get("composites", {})
        wanted_realm = composites.get("realm", [])
        wanted_client = composites.get("client", {})
        if not wanted_realm and not wanted_client:
            continue
        name = role["name"]
        current_reps = _api(base_url, ctx, token, "GET", f"/roles/{name}/composites") or []
        # A client role may share its name with a realm role, so the two are kept apart.
        current_realm = {c["name"] for c in current_reps if not c.get("clientRole")}
        current_client = {
            (c.get("containerId"), c["name"]) for c in current_reps if c.get("clientRole")
        }

        reps: list[dict] = []
        labels: list[str] = []
        for member in wanted_realm:
            if member not in current_realm:
                reps.append(_api(base_url, ctx, token, "GET", f"/roles/{member}"))
                labels.append(member)

        for client_id, members in wanted_client.items():
            if client_id not in client_uuids:
                client_uuids[client_id] = _client_uuid(base_url, ctx, token, client_id)
            uuid = client_uuids[client_id]
            if uuid is None:
                print(
                    f"  composites of {name} skipped: client {client_id} not found",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            for member in members:
                if (uuid, member) in current_client:
                    continue
                rep = _client_role(base_url, ctx, token, uuid, member)
                if rep is None:
                    print(
                        f"  composite of {name} skipped: client {client_id} has no role {member}",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue
                reps.append(rep)
                labels.append(f"{client_id}/{member}")

        if not reps:
            continue
        _api(base_url, ctx, token, "POST", f"/roles/{name}/composites", reps)
        added += len(reps)
        print(f"  composites added to {name}: {labels}", flush=True)
    return added


def _active_profile_clients(root: dict[str, str]) -> set[str]:
    """Client IDs the root .env's COMPOSE_PROFILES asks for."""
    profiles = {p.strip() for p in root.get("COMPOSE_PROFILES", "").split(",") if p.strip()}
    return {cid for profile, cids in PROFILE_CLIENTS.items() if profile in profiles for cid in cids}


def _has_secret_to_enforce(client: dict) -> bool:
    """Whether the rendered template carries a real secret for this client.

    Resource-server clients have none, and a placeholder must never become one."""
    return client.get("clientAuthenticatorType") == "client-secret" and not common.is_placeholder(
        client.get("secret", "")
    )


def _align_secret(base_url, ctx, token, client_uuid: str, client: dict) -> bool:
    """Set an existing client's secret to the one in the rendered template.

    The core `.env` is canonical for these clients: setup generates the secret there, bakes
    it into the realm and hands the same value to the service that signs in with it. A
    client that already existed, from an earlier add-on install for instance, keeps the
    secret it was created with, and the service is then refused at the token endpoint
    (HTTP 401, "Invalid client credentials"). Only the secret is written; the rest of the
    client is left as it is."""
    secret = client["secret"]
    current = _api(base_url, ctx, token, "GET", f"/clients/{client_uuid}/client-secret") or {}
    if current.get("value") == secret:
        return False
    _api(base_url, ctx, token, "PUT", f"/clients/{client_uuid}", {"secret": secret})
    print(f"  client secret updated: {client['clientId']}", flush=True)
    return True


def _sync_clients(base_url, ctx, token, realm_def: dict, wanted: set[str]) -> tuple[int, int]:
    """Create the wanted clients that the live realm lacks, from the rendered template
    (client secrets are already baked in), and align the secret of those that exist.

    Returns (clients created, secrets updated). Nothing else about an existing client
    is changed."""
    created = 0
    updated = 0
    for client in realm_def.get("clients", []):
        client_id = client["clientId"]
        if client_id not in wanted:
            continue
        matches = _api(
            base_url, ctx, token, "GET", f"/clients?clientId={urllib.parse.quote(client_id)}"
        )
        if matches:
            if _has_secret_to_enforce(client) and _align_secret(
                base_url, ctx, token, matches[0]["id"], client
            ):
                updated += 1
            continue
        if client.get("clientAuthenticatorType") == "client-secret" and not _has_secret_to_enforce(
            client
        ):
            # A placeholder would become the client's real secret. `setup` (or the
            # sync-env step of `start`) fills it in; the next start creates the client.
            print(
                f"  client skipped, its secret is not generated yet: {client_id}",
                file=sys.stderr,
                flush=True,
            )
            continue
        _api(base_url, ctx, token, "POST", "/clients", client)
        created += 1
        print(f"  client created: {client_id}", flush=True)
    return created, updated


def _sync_login_theme(base_url, ctx, token, realm_def: dict) -> int:
    """Give the existing clients the login theme the rendered template names for them.

    The theme is a per-client attribute (never the realm's), so a login that a papAIa
    service starts is branded and a direct Keycloak login is not. An attribute that is
    already set stays, whatever it holds: a theme chosen by hand is never overwritten.
    Keycloak's client update replaces the whole attribute map, so the existing
    attributes are sent along. Returns the number of clients changed."""
    changed = 0
    for client in realm_def.get("clients", []):
        theme = (client.get("attributes") or {}).get("login_theme")
        if not theme:
            continue
        matches = _api(
            base_url,
            ctx,
            token,
            "GET",
            f"/clients?clientId={urllib.parse.quote(client['clientId'])}",
        )
        if not matches:
            continue
        uuid = matches[0]["id"]
        current = _api(base_url, ctx, token, "GET", f"/clients/{uuid}") or {}
        attributes = dict(current.get("attributes") or {})
        if "login_theme" in attributes:
            continue
        attributes["login_theme"] = theme
        _api(base_url, ctx, token, "PUT", f"/clients/{uuid}", {"attributes": attributes})
        changed += 1
        print(f"  login theme set: {client['clientId']}", flush=True)
    return changed


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


# The keys of the realm's `smtpServer` that the relay block owns. Anything else an
# operator put there (a reply-to address, UTF-8 support) is kept as it is.
_SMTP_OWNED_KEYS = ("host", "port", "from", "fromDisplayName", "auth", "ssl", "starttls")
# The relay needs no login, so a live block that still carries one is stale.
_SMTP_LOGIN_KEYS = ("user", "password")


def _sync_smtp(base_url, ctx, token, realm_def: dict) -> str:
    """Make the live realm's mail server match the rendered one.

    The rendered realm names the relay (smtp-relay) while the `smtp` profile is on and
    configured, and has no mail server otherwise. Returns what happened:

      set        the live realm had no mail server; the relay block and the reset-password
                 link are switched on (once: an operator who turns the link off later is
                 not overruled, because later runs find a relay host and leave it alone)
      updated    the live relay block differed in a field this module owns
      cleared    the profile was switched off while the live block still points at the
                 relay; its host only resolves inside papaia-net, so leaving it would keep
                 "email a link" and "Forgot password?" on and let every send fail
      kept       the realm has a mail server of its own; never overwritten
      unchanged  nothing to do
    """
    desired = realm_def.get("smtpServer") or {}
    live = _api(base_url, ctx, token, "GET", "") or {}
    current = dict(live.get("smtpServer") or {})
    live_host = current.get("host", "")

    if not desired:
        if live_host != smtp.RELAY_HOST:
            return "unchanged"
        _api(base_url, ctx, token, "PUT", "", {"smtpServer": {}, "resetPasswordAllowed": False})
        print("  mail server cleared: the smtp profile is off", flush=True)
        return "cleared"

    if not live_host:
        _api(
            base_url,
            ctx,
            token,
            "PUT",
            "",
            {
                "smtpServer": desired,
                "resetPasswordAllowed": bool(realm_def.get("resetPasswordAllowed")),
            },
        )
        print(f"  mail server set: {desired['host']}", flush=True)
        return "set"
    if live_host != desired["host"]:
        print(
            f"Keycloak realm already uses the mail server '{live_host}'; left unchanged. To send"
            f" through the relay instead, set its host to {desired['host']} (port"
            f" {desired['port']}, no authentication, no encryption) in the realm settings, or"
            " clear the mail server and run 'papaia-ctl keycloak-role-sync' again.",
            file=sys.stderr,
            flush=True,
        )
        return "kept"

    stale = any(current.get(key) for key in _SMTP_LOGIN_KEYS)
    if not stale and all(current.get(key) == desired[key] for key in _SMTP_OWNED_KEYS):
        return "unchanged"
    merged = {k: v for k, v in current.items() if k not in _SMTP_LOGIN_KEYS}
    merged.update({key: desired[key] for key in _SMTP_OWNED_KEYS})
    _api(base_url, ctx, token, "PUT", "", {"smtpServer": merged})
    print(f"  mail server updated: {desired['host']}", flush=True)
    return "updated"


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

    base_url = _admin_base_url(root)
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
        # Clients before mappers: a mapper is only synced onto a client that exists.
        clients_created, secrets_updated = _sync_clients(
            base_url, ctx, token, realm_def, _active_profile_clients(root)
        )
        themes_set = _sync_login_theme(base_url, ctx, token, realm_def)
        mappers_added = _sync_protocol_mappers(base_url, ctx, token, realm_def)
        _sync_smtp(base_url, ctx, token, realm_def)
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
        f"{composites_added} composite edge(s) added, {clients_created} client(s) "
        f"created, {secrets_updated} client secret(s) updated, {themes_set} login "
        f"theme(s) set, {mappers_added} "
        f"protocol mapper(s) created, {migrated} user(s) migrated to "
        f"{_MIGRATION_TARGET_ROLE}.",
        flush=True,
    )
    return True
