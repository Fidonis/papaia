"""The service account of papaia-lifecycle, `svc-papaia-lifecycle`, kept by the realm sync.

While the Compose profile `lifecycle` is active, `papaia-ctl realm sync` makes sure the
`papaia` realm holds exactly this (with the master admin, every change one
`papaia.audit/1` row of the sync):

- the client `svc-papaia-lifecycle`: client_credentials with `private_key_jwt` (ES256)
  only, the public key of `$PAPAIA_CONFIG_DIR/security/service-accounts/
  svc-papaia-lifecycle/private-key.pem`, no sign-in flow, no password grant, no token
  exchange, `fullScopeAllowed: false`;
- its service-account user holds `realm-management` `view-events` (reading the admin
  events) and nothing else: no `manage-users`, no other role, no group;
- the group `papaia-persons`, a default group of the realm, with every account that is
  not a service account as a member;
- with admin permissions (`adminPermissionsEnabled`) switched on, one permission on the
  resource type Groups with the scopes `view-members` and `manage-members` for that
  group, granted to the client alone. That is the smallest set with which logout and
  consent removal work (measured against Keycloak 26.7.0 in stage 0); it is finer than
  `manage-users` by reach, not by operation: whoever holds the key can also change,
  disable or delete any member of the group (residual risk, docs/lifecycle.md);
- admin events stored (`adminEventsEnabled`), without representations, and kept for
  7 days (realm attribute `adminEventsExpiration`; sicherheit §1.12, EXI-P08): they
  carry actor, address and resource path, and papaia-audit is the record that lasts.
  A retention the operator set is kept.

Without the profile the client, its key folder and the permission are removed; the
group and the realm switches stay.
"""

from __future__ import annotations

import contextlib
import json
import urllib.parse

from . import realm_sync as rs
from . import service_account_keys as sak

CLIENT_ID = "svc-papaia-lifecycle"
PERSONS_GROUP = "papaia-persons"
PERMISSIONS_CLIENT = "admin-permissions"
POLICY = "papaia-lifecycle-account"
PERMISSION = "papaia-lifecycle-persons"
GROUP_SCOPES = ("manage-members", "view-members")
EVENT_ROLES = ("view-events",)
PROFILE = "lifecycle"
ADMIN_EVENTS_EXPIRATION = 7 * 24 * 3600
EXPIRATION_ATTRIBUTE = "adminEventsExpiration"
_PAGE = 100
# Next to the account key: the id of PERSONS_GROUP for papaia-lifecycle, which may list
# the group's members but not look the group up (same name in its lifecycle.py).
GROUP_FILE = "persons-group"

_FLAGS = {
    "protocol": "openid-connect",
    "publicClient": False,
    "bearerOnly": False,
    "standardFlowEnabled": False,
    "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False,
    "serviceAccountsEnabled": True,
    "fullScopeAllowed": False,
    "clientAuthenticatorType": "client-jwt",
}
_ATTRIBUTES = {
    "use.jwks.string": "true",
    "use.jwks.url": "false",
    "token.endpoint.auth.signing.alg": sak.ALGORITHM,
    rs.TOKEN_EXCHANGE: "false",
    rs.KIND: rs.SERVICE_ACCOUNT,
    "papaia.purpose": json.dumps(
        {"de": "Kontolebenszyklus und Entzug", "en": "Account lifecycle and revocation"},
        sort_keys=True,
        ensure_ascii=False,
    ),
}


def enabled(tree: dict) -> bool:
    profiles = tree.get("", {}).get("COMPOSE_PROFILES", "")
    return PROFILE in {p.strip() for p in profiles.split(",")}


def _seconds(value: object) -> int:
    """A retention attribute in seconds; 0 for none, an empty or a malformed value (no
    retention: events would be kept for ever)."""
    try:
        return int(str(value).strip())
    except ValueError:
        return 0


def _change(kind: str, name: str, action: str, operation: str, effect: str = "write"):
    return rs.Change(kind, name, action, f"lifecycle_{operation}", effect=effect)


def _paged(call, path: str) -> list[dict]:
    rows: list[dict] = []
    sep = "&" if "?" in path else "?"
    while True:
        batch = call("GET", f"{path}{sep}first={len(rows)}&max={_PAGE}") or []
        rows.extend(batch)
        if len(batch) < _PAGE:
            return rows


def _one(call, path: str, name: str, key: str = "name") -> dict | None:
    for item in call("GET", path) or []:
        if item.get(key) == name:
            return item
    return None


class _Align:
    def __init__(self, call, keys: sak.KeyStore, apply: bool, audit) -> None:
        self.call, self.keys, self.apply = call, keys, apply
        self.act = rs._Actions(call, apply, audit, master=True)

    # realm -------------------------------------------------------------
    def realm_switches(self) -> None:
        realm = self.call("GET", "") or {}
        if realm.get("adminPermissionsEnabled") is not True:
            self.act.do(
                _change(
                    "realm", rs.kcs._REALM, "admin permissions switched on", "admin_permissions"
                ),
                "PUT",
                "",
                {"adminPermissionsEnabled": True},
            )
        config = self.call("GET", "/events/config") or {}
        if config.get("adminEventsEnabled") is not True:
            body = dict(config, adminEventsEnabled=True)
            body.setdefault("adminEventsDetailsEnabled", False)
            self.act.do(
                _change("realm", rs.kcs._REALM, "admin events stored", "admin_events"),
                "PUT",
                "/events/config",
                body,
            )
        attributes = dict(realm.get("attributes") or {})
        if _seconds(attributes.get(EXPIRATION_ATTRIBUTE)) <= 0:
            attributes[EXPIRATION_ATTRIBUTE] = str(ADMIN_EVENTS_EXPIRATION)
            self.act.do(
                _change(
                    "realm",
                    rs.kcs._REALM,
                    f"admin events kept {ADMIN_EVENTS_EXPIRATION // 86400} days (retention)",
                    "admin_events_expiration",
                ),
                "PUT",
                "",
                {"attributes": attributes},
            )

    def group(self) -> str | None:
        query = urllib.parse.urlencode({"search": PERSONS_GROUP, "exact": "true"})
        group = _one(self.call, f"/groups?{query}", PERSONS_GROUP)
        if group is None:
            self.act.do(
                _change("group", PERSONS_GROUP, "created", "group"),
                "POST",
                "/groups",
                {"name": PERSONS_GROUP},
            )
            group = _one(self.call, f"/groups?{query}", PERSONS_GROUP) if self.apply else None
        if group is None:
            return None
        if _one(self.call, "/default-groups", PERSONS_GROUP) is None:
            self.act.do(
                _change("group", PERSONS_GROUP, "made a default group", "default_group"),
                "PUT",
                f"/default-groups/{group['id']}",
            )
        return group["id"]

    def members(self, group_id: str) -> None:
        """Every account but service accounts is a member; nothing else is."""
        members = {u["id"] for u in _paged(self.call, f"/groups/{group_id}/members")}
        for user in _paged(self.call, "/users?briefRepresentation=false"):
            service = bool(user.get("serviceAccountClientLink")) or str(
                user.get("username", "")
            ).startswith("service-account-")
            if not service and user["id"] not in members:
                self.act.do(
                    _change("user", user["id"], f"joined {PERSONS_GROUP}", "group_member"),
                    "PUT",
                    f"/users/{user['id']}/groups/{group_id}",
                )
            elif service and user["id"] in members:
                self.act.do(
                    _change("user", user["id"], f"left {PERSONS_GROUP}", "group_member", "delete"),
                    "DELETE",
                    f"/users/{user['id']}/groups/{group_id}",
                )

    def persons_group_file(self, group_id: str) -> None:
        """The group's id for the service, in its account folder (not a secret; 0600
        like the key, which the service reads from the same read-only mount)."""
        data = f"{group_id}\n".encode("ascii")
        if self.keys.read(CLIENT_ID, GROUP_FILE) == data:
            return
        change = _change(
            rs.SERVICE_ACCOUNT,
            CLIENT_ID,
            f"id of {PERSONS_GROUP} written for the service",
            "group_file",
        )
        self.act.changes.append(change)
        print(f"{'  ' if self.apply else 'fail: '}{change.kind} {change.name}: {change.action}")
        if not self.apply:
            return
        try:
            self.keys.write(CLIENT_ID, GROUP_FILE, data)
        except OSError:
            self.act._audit(change, "error", "local_write")
            raise
        self.act._audit(change, "allowed")

    # client --------------------------------------------------------------
    def client(self) -> dict | None:
        jwk = self.keys.public_jwk(CLIENT_ID)
        query = urllib.parse.quote(CLIENT_ID)
        found = self.call("GET", f"/clients?clientId={query}") or []
        current = found[0] if found else None
        if jwk is None and self.apply:
            jwk = self.keys.generate(CLIENT_ID)
        attributes = dict(_ATTRIBUTES)
        attributes["jwks.string"] = json.dumps({"keys": [jwk]}, sort_keys=True) if jwk else ""
        wanted = dict(_FLAGS, clientId=CLIENT_ID, attributes=attributes)
        if current is None:
            self.act.do(
                _change(rs.SERVICE_ACCOUNT, CLIENT_ID, "created", "client"),
                "POST",
                "/clients",
                dict(wanted, attributes=dict(attributes, **{rs.ROTATED_AT: rs._now_iso()})),
            )
        else:
            have = current.get("attributes") or {}
            off = [k for k, v in _FLAGS.items() if current.get(k) != v]
            off += [k for k, v in attributes.items() if k != "jwks.string" and have.get(k) != v]
            try:
                keys = json.loads(have.get("jwks.string") or "{}").get("keys")
            except (ValueError, AttributeError):
                keys = None
            if keys != ([jwk] if jwk else None):
                off.append("jwks.string")
            if off:
                merged = dict(have, **attributes)
                if "jwks.string" in off:
                    merged[rs.ROTATED_AT] = rs._now_iso()
                self.act.do(
                    _change(
                        rs.SERVICE_ACCOUNT,
                        CLIENT_ID,
                        f"realigned: {', '.join(sorted(off))}",
                        "client",
                    ),
                    "PUT",
                    f"/clients/{current['id']}",
                    dict(wanted, attributes=merged),
                )
        if not self.apply and current is None:
            return None
        found = self.call("GET", f"/clients?clientId={query}") or []
        return found[0] if found else None

    def account_user(self, client: dict) -> None:
        """Exactly `view-events` of realm-management: in the user's mappings and, since
        the client has no full scope, in the client's scope."""
        management = _one(
            self.call, "/clients?clientId=realm-management", "realm-management", "clientId"
        )
        if management is None:
            raise rs.RealmSyncError("the realm has no realm-management client")
        rm = management["id"]
        wanted = [self.call("GET", f"/clients/{rm}/roles/{r}") for r in EVENT_ROLES]
        user = self.call("GET", f"/clients/{client['id']}/service-account-user")["id"]
        for group in self.call("GET", f"/users/{user}/groups") or []:
            self.act.do(
                _change(
                    rs.SERVICE_ACCOUNT,
                    CLIENT_ID,
                    f"left group {group.get('name')}",
                    "account_group",
                    "delete",
                ),
                "DELETE",
                f"/users/{user}/groups/{group['id']}",
            )
        mappings = self.call("GET", f"/users/{user}/role-mappings") or {}
        extra_realm = [
            r
            for r in mappings.get("realmMappings") or []
            if r["name"] != f"default-roles-{rs.kcs._REALM}"
        ]
        if extra_realm:
            self.act.do(
                _change(
                    rs.SERVICE_ACCOUNT,
                    CLIENT_ID,
                    f"realm roles out of its rights: {rs._names(extra_realm)}",
                    "account_roles",
                    "delete",
                ),
                "DELETE",
                f"/users/{user}/role-mappings/realm",
                extra_realm,
            )
        for name, entry in sorted((mappings.get("clientMappings") or {}).items()):
            roles = entry.get("mappings") or []
            extra = [
                r for r in roles if not (name == "realm-management" and r["name"] in EVENT_ROLES)
            ]
            if extra:
                self.act.do(
                    _change(
                        rs.SERVICE_ACCOUNT,
                        CLIENT_ID,
                        f"{name} roles out of its rights: {rs._names(extra)}",
                        "account_roles",
                        "delete",
                    ),
                    "DELETE",
                    f"/users/{user}/role-mappings/clients/{entry['id']}",
                    extra,
                )
        have = {
            r["name"]
            for r in ((mappings.get("clientMappings") or {}).get("realm-management") or {}).get(
                "mappings"
            )
            or []
        }
        missing = [r for r in wanted if r["name"] not in have]
        if missing:
            self.act.do(
                _change(
                    rs.SERVICE_ACCOUNT,
                    CLIENT_ID,
                    f"realm-management roles granted: {rs._names(missing)}",
                    "account_roles",
                ),
                "POST",
                f"/users/{user}/role-mappings/clients/{rm}",
                missing,
            )
        scope = self.call("GET", f"/clients/{client['id']}/scope-mappings/clients/{rm}") or []
        if {r["name"] for r in scope} != set(EVENT_ROLES):
            extra = [r for r in scope if r["name"] not in EVENT_ROLES]
            if extra:
                self.act.do(
                    _change(
                        rs.SERVICE_ACCOUNT,
                        CLIENT_ID,
                        f"token scope out of its rights: {rs._names(extra)}",
                        "account_scope",
                        "delete",
                    ),
                    "DELETE",
                    f"/clients/{client['id']}/scope-mappings/clients/{rm}",
                    extra,
                )
            add = [r for r in wanted if r["name"] not in {s["name"] for s in scope}]
            if add:
                self.act.do(
                    _change(
                        rs.SERVICE_ACCOUNT,
                        CLIENT_ID,
                        f"token scope: {rs._names(add)}",
                        "account_scope",
                    ),
                    "POST",
                    f"/clients/{client['id']}/scope-mappings/clients/{rm}",
                    add,
                )

    # admin permission ---------------------------------------------------
    def _authz(self) -> str | None:
        client = _one(
            self.call, f"/clients?clientId={PERMISSIONS_CLIENT}", PERMISSIONS_CLIENT, "clientId"
        )
        return f"/clients/{client['id']}/authz/resource-server" if client else None

    def permission(self, client: dict | None, group_id: str | None) -> None:
        base = self._authz()
        if base is None or client is None or group_id is None:
            return
        policy = _one(self.call, f"{base}/policy?name={POLICY}", POLICY)
        policy_body = {
            "name": POLICY,
            "type": "client",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "clients": [client["id"]],
        }
        if policy is None:
            self.act.do(
                _change("admin-permission", POLICY, "created", "policy"),
                "POST",
                f"{base}/policy/client",
                policy_body,
            )
            policy = _one(self.call, f"{base}/policy?name={POLICY}", POLICY) if self.apply else None
        else:
            detail = self.call("GET", f"{base}/policy/client/{policy['id']}") or {}
            if detail.get("clients") != [client["id"]] or detail.get("logic") != "POSITIVE":
                self.act.do(
                    _change("admin-permission", POLICY, "realigned to the client", "policy"),
                    "PUT",
                    f"{base}/policy/client/{policy['id']}",
                    dict(policy_body, id=policy["id"]),
                )
        if policy is None:
            return
        body = {
            "name": PERMISSION,
            "type": "scope",
            "resourceType": "Groups",
            "resources": [group_id],
            "scopes": list(GROUP_SCOPES),
            "policies": [policy["id"]],
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
        }
        perm = _one(self.call, f"{base}/permission?name={PERMISSION}", PERMISSION)
        if perm is None:
            self.act.do(
                _change("admin-permission", PERMISSION, "created", "permission"),
                "POST",
                f"{base}/permission/scope",
                body,
            )
            return
        scopes = {s["name"] for s in self.call("GET", f"{base}/policy/{perm['id']}/scopes") or []}
        policies = {
            p["id"]
            for p in self.call("GET", f"{base}/policy/{perm['id']}/associatedPolicies") or []
        }
        resources = self.call("GET", f"{base}/policy/{perm['id']}/resources") or []
        names = {r.get("name") for r in resources}
        if (
            scopes != set(GROUP_SCOPES)
            or policies != {policy["id"]}
            or names != {group_id}
            or perm.get("logic") != "POSITIVE"
            or perm.get("resourceType", "Groups") != "Groups"
        ):
            self.act.do(
                _change("admin-permission", PERMISSION, "realigned", "permission"),
                "PUT",
                f"{base}/permission/scope/{perm['id']}",
                dict(body, id=perm["id"]),
            )

    # removal -------------------------------------------------------------
    def remove(self) -> None:
        base = self._authz()
        if base is not None:
            for name in (PERMISSION, POLICY):
                item = _one(self.call, f"{base}/policy?name={name}", name)
                if item is not None:
                    self.act.do(
                        _change(
                            "admin-permission", name, "removed, profile off", "permission", "delete"
                        ),
                        "DELETE",
                        f"{base}/policy/{item['id']}",
                    )
        found = self.call("GET", f"/clients?clientId={urllib.parse.quote(CLIENT_ID)}") or []
        if found:
            self.act.do(
                _change(
                    rs.SERVICE_ACCOUNT,
                    CLIENT_ID,
                    "removed, profile lifecycle is off",
                    "client",
                    "delete",
                ),
                "DELETE",
                f"/clients/{found[0]['id']}",
            )
        if self.keys.public_jwk(CLIENT_ID) is not None:
            if self.apply:
                with contextlib.suppress(ValueError):
                    self.keys.remove(CLIENT_ID)
            else:
                self.act.changes.append(
                    _change(rs.SERVICE_ACCOUNT, CLIENT_ID, "key folder left", "key", "delete")
                )


def align(call, keys: sak.KeyStore, *, enabled: bool, apply: bool, audit=None) -> list:
    """Compare (and with `apply` correct) the lifecycle account; `call` is the master
    admin's Admin API call of the `papaia` realm. Returns the deviations."""
    run = _Align(call, keys, apply, audit)
    if not enabled:
        run.remove()
        return run.act.changes
    run.realm_switches()
    group = run.group()
    client = run.client()
    if client is not None:
        run.account_user(client)
    run.permission(client, group)
    if group is not None:
        run.persons_group_file(group)
        run.members(group)
    return run.act.changes
