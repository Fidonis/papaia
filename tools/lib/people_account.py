"""The service account of papaia-people, `svc-papaia-people`, kept by the realm sync.

While the Compose profile `people` is active, `papaia-ctl realm sync` makes sure the
`papaia` realm holds exactly this (with the master admin, every change one
`papaia.audit/1` row of the sync; sicherheit §1.4, §1.9, RE-51):

- the client `svc-papaia-people`: client_credentials with `private_key_jwt` (ES256)
  only, the public key of `$PAPAIA_CONFIG_DIR/security/service-accounts/
  svc-papaia-people/private-key.pem`, no sign-in flow, no password grant, no token
  exchange, `fullScopeAllowed: false`;
- its service-account user holds `realm-management` `query-users` and `view-users` and
  nothing else: no write right, no other client or realm role, no group. `query-users`
  alone finds nobody and cannot read role mappings, so `view-users` is needed; Keycloak
  makes `view-users` a composite that also holds `query-groups` (measured against
  Keycloak 26.7.0 in stage 0, MN-16), which is within the bound of security 1.9;
- the same two roles, and only these, in the client's token scope.

The audience `papaia-people` itself (a bearer-only client and the exchange scope
`aud-papaia-people`, persons only, paired with `assist-gate` alone) is part of the plan
of `realm_sync` while the profile is active (`core_audiences`).

Without the profile the client and its key folder are removed.
"""

from __future__ import annotations

import contextlib
import json
import urllib.parse

from . import realm_sync as rs
from . import service_account_keys as sak

CLIENT_ID = "svc-papaia-people"
AUDIENCE = "papaia-people"
PROFILE = "people"
DIRECTORY_ROLES = ("query-users", "view-users")

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
        {"de": "Kern-Personensuche", "en": "Core people lookup"},
        sort_keys=True,
        ensure_ascii=False,
    ),
}


def enabled(tree: dict) -> bool:
    profiles = tree.get("", {}).get("COMPOSE_PROFILES", "")
    return PROFILE in {p.strip() for p in profiles.split(",")}


def core_audiences(tree: dict) -> frozenset[str]:
    """The audiences the core serves itself under the active profiles."""
    return frozenset({AUDIENCE}) if enabled(tree) else frozenset()


def _change(name: str, action: str, operation: str, effect: str = "write") -> rs.Change:
    return rs.Change(rs.SERVICE_ACCOUNT, name, action, f"people_{operation}", effect=effect)


class _Align:
    def __init__(self, call, keys: sak.KeyStore, apply: bool, audit) -> None:
        self.call, self.keys, self.apply = call, keys, apply
        self.act = rs._Actions(call, apply, audit, master=True)

    def _client(self) -> dict | None:
        found = self.call("GET", f"/clients?clientId={urllib.parse.quote(CLIENT_ID)}") or []
        return found[0] if found else None

    def client(self) -> dict | None:
        current = self._client()
        jwk = self.keys.public_jwk(CLIENT_ID)
        if jwk is None and self.apply:
            jwk = self.keys.generate(CLIENT_ID)
        attributes = dict(_ATTRIBUTES)
        attributes["jwks.string"] = json.dumps({"keys": [jwk]}, sort_keys=True) if jwk else ""
        wanted = dict(_FLAGS, clientId=CLIENT_ID, attributes=attributes)
        if current is None:
            self.act.do(
                _change(CLIENT_ID, "created", "client"),
                "POST",
                "/clients",
                dict(wanted, attributes=dict(attributes, **{rs.ROTATED_AT: rs._now_iso()})),
            )
            return self._client() if self.apply else None
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
                _change(CLIENT_ID, f"realigned: {', '.join(sorted(off))}", "client"),
                "PUT",
                f"/clients/{current['id']}",
                dict(wanted, attributes=merged),
            )
        return current

    def account_user(self, client: dict) -> None:
        """Exactly the two directory roles of realm-management, in the user's mappings
        and in the client's token scope; no group, no other role."""
        found = self.call("GET", "/clients?clientId=realm-management") or []
        management = next((c for c in found if c.get("clientId") == "realm-management"), None)
        if management is None:
            raise rs.RealmSyncError("the realm has no realm-management client")
        rm = management["id"]
        wanted = [self.call("GET", f"/clients/{rm}/roles/{r}") for r in DIRECTORY_ROLES]
        user = self.call("GET", f"/clients/{client['id']}/service-account-user")["id"]
        for group in self.call("GET", f"/users/{user}/groups") or []:
            self.act.do(
                _change(CLIENT_ID, f"left group {group.get('name')}", "account_group", "delete"),
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
                    CLIENT_ID,
                    f"realm roles out of its rights: {rs._names(extra_realm)}",
                    "account_roles",
                    "delete",
                ),
                "DELETE",
                f"/users/{user}/role-mappings/realm",
                extra_realm,
            )
        held: set[str] = set()
        for name, entry in sorted((mappings.get("clientMappings") or {}).items()):
            roles = entry.get("mappings") or []
            own = name == "realm-management"
            extra = [r for r in roles if not (own and r["name"] in DIRECTORY_ROLES)]
            if own:
                held = {r["name"] for r in roles} - {r["name"] for r in extra}
            if extra:
                self.act.do(
                    _change(
                        CLIENT_ID,
                        f"{name} roles out of its rights: {rs._names(extra)}",
                        "account_roles",
                        "delete",
                    ),
                    "DELETE",
                    f"/users/{user}/role-mappings/clients/{entry['id']}",
                    extra,
                )
        missing = [r for r in wanted if r["name"] not in held]
        if missing:
            self.act.do(
                _change(
                    CLIENT_ID,
                    f"realm-management roles granted: {rs._names(missing)}",
                    "account_roles",
                ),
                "POST",
                f"/users/{user}/role-mappings/clients/{rm}",
                missing,
            )
        scope = self.call("GET", f"/clients/{client['id']}/scope-mappings/clients/{rm}") or []
        extra = [r for r in scope if r["name"] not in DIRECTORY_ROLES]
        if extra:
            self.act.do(
                _change(
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
                _change(CLIENT_ID, f"token scope: {rs._names(add)}", "account_scope"),
                "POST",
                f"/clients/{client['id']}/scope-mappings/clients/{rm}",
                add,
            )

    def remove(self) -> None:
        current = self._client()
        if current is not None:
            self.act.do(
                _change(CLIENT_ID, f"removed, profile {PROFILE} is off", "client", "delete"),
                "DELETE",
                f"/clients/{current['id']}",
            )
        if self.keys.public_jwk(CLIENT_ID) is not None:
            if self.apply:
                with contextlib.suppress(ValueError):
                    self.keys.remove(CLIENT_ID)
            else:
                self.act.changes.append(_change(CLIENT_ID, "key folder left", "key", "delete"))


def align(call, keys: sak.KeyStore, *, enabled: bool, apply: bool, audit=None) -> list:
    """Compare (and with `apply` correct) the people account; `call` is the master
    admin's Admin API call of the `papaia` realm. Returns the deviations."""
    run = _Align(call, keys, apply, audit)
    if not enabled:
        run.remove()
        return run.act.changes
    client = run.client()
    if client is not None:
        run.account_user(client)
    return run.act.changes
