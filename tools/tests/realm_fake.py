"""In-memory stand-in for the parts of Keycloak's Admin REST API that the realm sync uses.

It is called like `realm_sync.AdminApi.call(method, path, body)`, so the sync runs
unmodified against it. It starts like a fresh Keycloak realm: the built-in clients and
client scopes, with `offline_access` among the realm's default optional scopes and on
every client, the realm's default roles, `realm-management` with its client roles, a
service-account user for every client created with `serviceAccountsEnabled` (with Keycloak's
`service_account` scope as a default scope of that client), groups, and the
`offline_access` scope mapping the `offline_access` role, and the realm's client policies
and profiles (empty, as in a fresh realm). Every write
is counted in `writes`. A role that does not exist is a `NotFound`, as Keycloak answers
with HTTP 404. Clients can be deleted; turning `serviceAccountsEnabled` on or off creates
or removes the service-account user. The realm's event settings and stored sign-in
events (`events`, newest first) are kept as well.
"""

from __future__ import annotations

import copy
import itertools
import re
import urllib.parse

BUILTIN_DEFAULT = ["web-origins", "acr", "profile", "roles", "basic", "email"]
BUILTIN_OPTIONAL = ["address", "phone", "organization", "offline_access", "microprofile-jwt"]
BUILTIN_CLIENTS = [
    "account",
    "account-console",
    "admin-cli",
    "broker",
    "realm-management",
    "security-admin-console",
]


REALM_MANAGEMENT_ROLES = [
    "realm-admin",
    "manage-realm",
    "manage-clients",
    "manage-users",
    "view-users",
    "query-users",
    "view-realm",
    "view-clients",
]


class NotFound(Exception):
    pass


class BadRequest(Exception):
    pass


class FakeRealm:
    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self.writes: list[tuple[str, str]] = []
        self.roles: dict[str, dict] = {}
        self.scopes: dict[str, dict] = {}
        self.clients: dict[str, dict] = {}
        self.users: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        # realm-level client policies and profiles (Keycloak's global ones are not listed)
        self.policies: list[dict] = []
        self.profiles: list[dict] = []
        self.events_config: dict = {
            "eventsEnabled": False,
            "eventsListeners": ["jboss-logging"],
            "enabledEventTypes": [],
            "adminEventsEnabled": False,
            "adminEventsDetailsEnabled": False,
        }
        self.events: list[dict] = []
        for name in ("offline_access", "uma_authorization", "default-roles-papaia"):
            self._add_role(name)
        self.roles["default-roles-papaia"]["_composites"] = {"offline_access", "uma_authorization"}
        self.roles["default-roles-papaia"]["composite"] = True
        for name in BUILTIN_DEFAULT + BUILTIN_OPTIONAL:
            self._add_scope({"name": name, "protocol": "openid-connect"})
        # Keycloak's own scope of service-account clients; no realm default
        self._add_scope({"name": "service_account", "protocol": "openid-connect"})
        self.scope_by_name("offline_access")["_role_scope"].add("offline_access")
        self.default_optional = [self._scope_id(n) for n in BUILTIN_OPTIONAL]
        self.default_default = [self._scope_id(n) for n in BUILTIN_DEFAULT]
        for client_id in BUILTIN_CLIENTS:
            bearer = client_id in ("broker", "realm-management")
            self._add_client({"clientId": client_id, "bearerOnly": bearer})
        rm = self.by_client_id("realm-management")
        rm["_roles"] = {
            name: {
                "id": self._id("crole"),
                "name": name,
                "composite": False,
                "clientRole": True,
                "_composites": set(),
                "_client_composites": set(),
            }
            for name in REALM_MANAGEMENT_ROLES
        }

    # helpers -------------------------------------------------------------
    def _id(self, prefix: str) -> str:
        return f"{prefix}-{next(self._ids)}"

    def _scope_id(self, name: str) -> str:
        return next(s["id"] for s in self.scopes.values() if s["name"] == name)

    def _add_role(self, name: str, attributes: dict | None = None) -> None:
        self.roles[name] = {
            "id": self._id("role"),
            "name": name,
            "description": "",
            "composite": False,
            "clientRole": False,
            "attributes": copy.deepcopy(attributes or {}),
            "_composites": set(),
            "_client_composites": set(),
        }

    def add_client_composite(self, role: str, client_id: str, client_role: str) -> None:
        """Make a realm role a composite that includes a client role (as the realm
        template's papaia-admin includes realm-management roles)."""
        self.roles[role]["_client_composites"].add((client_id, client_role))
        self.roles[role]["composite"] = True

    def add_client_role_composite(
        self, client_id: str, name: str, *, realm: str | None = None, client: tuple = ()
    ) -> None:
        """Make a client role a composite that includes a realm role or a client role
        (`client` = (client id, role))."""
        role = self.by_client_id(client_id)["_roles"][name]
        if realm:
            role["_composites"].add(realm)
        if client:
            role["_client_composites"].add(client)
        role["composite"] = True

    def add_client_role(self, client_id: str, name: str) -> None:
        """A client role of any client (Keycloak puts a client's own roles into its token
        scope whatever `fullScopeAllowed` says)."""
        self.by_client_id(client_id).setdefault("_roles", {})[name] = {
            "id": self._id("crole"),
            "name": name,
            "description": "",
            "composite": False,
            "clientRole": True,
            "_composites": set(),
            "_client_composites": set(),
        }

    def add_user(
        self,
        username: str,
        *,
        realm_roles: set[str] = frozenset(),
        groups: tuple[str, ...] = (),
        enabled: bool = True,
    ) -> str:
        """A person: `realm_roles` mapped directly, member of the groups (ids) given."""
        uid = self._id("user")
        self.users[uid] = {
            "id": uid,
            "username": username,
            "enabled": enabled,
            "_realm": {"default-roles-papaia", *realm_roles},
            "_clients": {},
            "_groups": set(groups),
        }
        return uid

    def add_realm_role(self, name: str, composites: set[str] = frozenset()) -> None:
        """A realm role created by hand, optionally a composite of other realm roles."""
        self._add_role(name)
        self.roles[name]["_composites"] = set(composites)
        self.roles[name]["composite"] = bool(composites)

    def _effective_realm(self, user: dict) -> set[str]:
        """Keycloak's effective realm roles of a user: direct and group mappings with
        every composite expanded."""
        todo = list(user["_realm"])
        for gid in user["_groups"]:
            todo += self.groups[gid]["_realm"]
        seen: set[str] = set()
        while todo:
            name = todo.pop()
            if name in seen or name not in self.roles:
                continue
            seen.add(name)
            todo += self.roles[name]["_composites"]
        return seen

    def add_group(self, name: str, realm_roles: set[str] = frozenset()) -> str:
        gid = self._id("group")
        self.groups[gid] = {"id": gid, "name": name, "path": f"/{name}", "_realm": set(realm_roles)}
        return gid

    def _client_role(self, client: dict, name: str) -> dict:
        role = client.get("_roles", {}).get(name)
        if role is None:
            raise NotFound(name)
        rep = {k: copy.deepcopy(v) for k, v in role.items() if not k.startswith("_")}
        return dict(rep, containerId=client["id"])

    def _composite_reps(self, role: dict) -> list[dict]:
        reps = [self._role_rep(n) for n in sorted(role["_composites"])]
        for client_id, name in sorted(role["_client_composites"]):
            reps.append(self._client_role(self.by_client_id(client_id), name))
        return reps

    def _role_by_id(self, role_id: str) -> dict:
        for role in self.roles.values():
            if role["id"] == role_id:
                return role
        for client in self.clients.values():
            for role in client.get("_roles", {}).values():
                if role["id"] == role_id:
                    return role
        raise NotFound(role_id)

    def scope_by_name(self, name: str) -> dict:
        return next(s for s in self.scopes.values() if s["name"] == name)

    def _scope_rep(self, scope: dict) -> dict:
        return {k: copy.deepcopy(v) for k, v in scope.items() if not k.startswith("_")}

    def _mappings(self, realm_names: set[str], client_roles: dict[str, set[str]]) -> dict:
        rep: dict = {}
        if realm_names:
            rep["realmMappings"] = [self._role_rep(n) for n in sorted(realm_names)]
        clients = {}
        for cid, names in client_roles.items():
            if names:
                client = self.clients[cid]
                clients[client["clientId"]] = {
                    "id": cid,
                    "client": client["clientId"],
                    "mappings": [self._client_role(client, n) for n in sorted(names)],
                }
        if clients:
            rep["clientMappings"] = clients
        return rep

    def _check_policies(self, policies: list[dict]) -> None:
        """Keycloak 26.7.0 refuses a policy whose `client-scopes` condition names a
        scope that does not exist (HTTP 400 `Client scopes not allowed`)."""
        names = {s["name"] for s in self.scopes.values()}
        for policy in policies:
            for condition in policy.get("conditions") or []:
                if condition.get("condition") != "client-scopes":
                    continue
                missing = set(condition["configuration"]["scopes"]) - names
                if missing:
                    raise BadRequest(f"Client scopes not allowed: {sorted(missing)}")

    def policy(self, name: str) -> dict:
        return next(p for p in self.policies if p["name"] == name)

    def profile(self, name: str) -> dict:
        return next(p for p in self.profiles if p["name"] == name)

    def service_account_user(self, client_id: str) -> dict:
        uid = self.by_client_id(client_id)["_service_user"]
        return self.users[uid]

    def _add_scope(self, rep: dict) -> None:
        if any(s["name"] == rep["name"] for s in self.scopes.values()):
            raise ValueError(f"duplicate scope {rep['name']}")
        scope = copy.deepcopy(rep)
        scope["id"] = self._id("scope")
        scope.setdefault("attributes", {})
        scope["protocolMappers"] = [
            dict(m, id=self._id("mapper")) for m in scope.get("protocolMappers", [])
        ]
        scope["_role_scope"] = set()
        scope["_client_scope"] = {}
        self.scopes[scope["id"]] = scope

    def _add_client(self, rep: dict) -> None:
        if any(c["clientId"] == rep["clientId"] for c in self.clients.values()):
            raise ValueError(f"duplicate client {rep['clientId']}")
        client = {
            "bearerOnly": False,
            "publicClient": True,
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": False,
            "fullScopeAllowed": True,
            "attributes": {},
        }
        client.update(copy.deepcopy(rep))
        client["id"] = self._id("client")
        names = {s["name"]: s["id"] for s in self.scopes.values()}
        default = rep.get("defaultClientScopes")
        optional = rep.get("optionalClientScopes")
        client["_default"] = (
            [names[n] for n in default if n in names]
            if default is not None
            else list(self.default_default)
        )
        client["_optional"] = (
            [names[n] for n in optional if n in names]
            if optional is not None
            else list(self.default_optional)
        )
        client.pop("defaultClientScopes", None)
        client.pop("optionalClientScopes", None)
        client["_role_scope"] = set()
        client["_client_scope"] = {}
        client["protocolMappers"] = [
            dict(m, id=self._id("mapper")) for m in rep.get("protocolMappers", [])
        ]
        if client.get("publicClient") is False and not client.get("bearerOnly"):
            client.setdefault("secret", "generated-by-keycloak")
        self.clients[client["id"]] = client
        if client.get("serviceAccountsEnabled"):
            self._add_service_user(client)

    def _add_service_user(self, client: dict) -> None:
        uid = self._id("user")
        self.users[uid] = {
            "id": uid,
            "username": f"service-account-{client['clientId']}",
            "enabled": True,
            "serviceAccountClientLink": client["id"],
            "_realm": {"default-roles-papaia"},
            "_clients": {},
            "_groups": set(),
        }
        client["_service_user"] = uid
        sid = self._scope_id("service_account")
        if sid not in client["_default"]:
            client["_default"].append(sid)

    def sign_in(self, client_id: str, at_ms: int) -> None:
        """A stored CLIENT_LOGIN event, as Keycloak records it when events are on."""
        if self.events_config["eventsEnabled"] and "CLIENT_LOGIN" in (
            self.events_config["enabledEventTypes"] or ["CLIENT_LOGIN"]
        ):
            self.events.insert(0, {"time": at_ms, "type": "CLIENT_LOGIN", "clientId": client_id})

    def client_rep(self, client: dict) -> dict:
        rep = {k: copy.deepcopy(v) for k, v in client.items() if not k.startswith("_")}
        if not rep.get("protocolMappers"):
            rep.pop("protocolMappers", None)
        rep["defaultClientScopes"] = [self.scopes[i]["name"] for i in client["_default"]]
        rep["optionalClientScopes"] = [self.scopes[i]["name"] for i in client["_optional"]]
        return rep

    def by_client_id(self, client_id: str) -> dict:
        return next(c for c in self.clients.values() if c["clientId"] == client_id)

    def scope_names(self, client_id: str, kind: str) -> set[str]:
        client = self.by_client_id(client_id)
        return {self.scopes[i]["name"] for i in client[f"_{kind}"]}

    def _role_rep(self, name: str) -> dict:
        role = self.roles[name]
        return {k: copy.deepcopy(v) for k, v in role.items() if not k.startswith("_")}

    def _map(self, held: set[str], client: dict, method: str, body):
        if method == "GET":
            return [self._client_role(client, n) for n in sorted(held)]
        names = {r["name"] for r in body}
        if method == "POST":
            held |= names
        elif method == "DELETE":
            held -= names
        return None

    # the API ---------------------------------------------------------------
    def call(self, method: str, path: str, body=None):
        if method != "GET":
            self.writes.append((method, path))
        parts = urllib.parse.urlsplit(path)
        route = parts.path
        query = urllib.parse.parse_qs(parts.query)

        if route == "/roles" and method == "GET":
            return [self._role_rep(n) for n in self.roles]
        if route == "/roles" and method == "POST":
            self._add_role(body["name"], body.get("attributes"))
            self.roles[body["name"]]["description"] = body.get("description", "")
            return None
        m = re.fullmatch(r"/roles/([^/]+)", route)
        if m and method == "GET":
            name = urllib.parse.unquote(m.group(1))
            if name not in self.roles:
                raise NotFound(path)
            return self._role_rep(name)
        m = re.fullmatch(r"/roles/([^/]+)/composites/realm", route)
        if m and method == "GET":
            name = urllib.parse.unquote(m.group(1))
            return [self._role_rep(n) for n in sorted(self.roles[name]["_composites"])]
        m = re.fullmatch(r"/roles/([^/]+)/composites", route)
        if m and method == "GET":
            return self._composite_reps(self.roles[urllib.parse.unquote(m.group(1))])
        if m and method == "POST":
            name = urllib.parse.unquote(m.group(1))
            self.roles[name]["_composites"].update(r["name"] for r in body)
            self.roles[name]["composite"] = True
            return None
        if m and method == "DELETE":
            role = self.roles[urllib.parse.unquote(m.group(1))]
            role["_composites"] -= {r["name"] for r in body if not r.get("clientRole")}
            role["_client_composites"] -= {
                (self.clients[r["containerId"]]["clientId"], r["name"])
                for r in body
                if r.get("clientRole")
            }
            role["composite"] = bool(role["_composites"] or role["_client_composites"])
            return None
        m = re.fullmatch(r"/roles-by-id/([^/]+)/composites", route)
        if m and method == "GET":
            return self._composite_reps(self._role_by_id(m.group(1)))
        if m and method == "DELETE":
            role = self._role_by_id(m.group(1))
            role["_composites"] -= {r["name"] for r in body if not r.get("clientRole")}
            role["_client_composites"] -= {
                (self.clients[r["containerId"]]["clientId"], r["name"])
                for r in body
                if r.get("clientRole")
            }
            role["composite"] = bool(role["_composites"] or role["_client_composites"])
            return None

        if route == "/client-scopes" and method == "GET":
            return [self._scope_rep(s) for s in self.scopes.values()]
        if route == "/client-scopes" and method == "POST":
            self._add_scope(body)
            return None
        m = re.fullmatch(r"/client-scopes/([^/]+)", route)
        if m and method == "PUT":
            scope = self.scopes[m.group(1)]
            for key in ("name", "protocol"):
                if body.get(key) is not None:
                    scope[key] = body[key]
            scope["attributes"].update(copy.deepcopy(body.get("attributes") or {}))
            return None
        if m and method == "DELETE":
            sid = m.group(1)
            del self.scopes[sid]
            for target in (self.default_default, self.default_optional):
                if sid in target:
                    target.remove(sid)
            for client in self.clients.values():
                for kind in ("_default", "_optional"):
                    if sid in client[kind]:
                        client[kind].remove(sid)
            return None
        m = re.fullmatch(r"/client-scopes/([^/]+)/scope-mappings", route)
        if m and method == "GET":
            scope = self.scopes[m.group(1)]
            return self._mappings(scope["_role_scope"], scope["_client_scope"])
        m = re.fullmatch(r"/client-scopes/([^/]+)/scope-mappings/realm", route)
        if m:
            held = self.scopes[m.group(1)]["_role_scope"]
            if method == "GET":
                return [self._role_rep(n) for n in sorted(held)]
            names = {r["name"] for r in body}
            if method == "POST":
                held |= names
            elif method == "DELETE":
                held -= names
            return None
        m = re.fullmatch(r"/client-scopes/([^/]+)/scope-mappings/clients/([^/]+)", route)
        if m:
            held = self.scopes[m.group(1)]["_client_scope"].setdefault(m.group(2), set())
            return self._map(held, self.clients[m.group(2)], method, body)
        m = re.fullmatch(r"/client-scopes/([^/]+)/protocol-mappers/models", route)
        if m and method == "POST":
            self.scopes[m.group(1)]["protocolMappers"].append(dict(body, id=self._id("mapper")))
            return None
        m = re.fullmatch(r"/client-scopes/([^/]+)/protocol-mappers/models/([^/]+)", route)
        if m and method == "DELETE":
            scope = self.scopes[m.group(1)]
            scope["protocolMappers"] = [
                x for x in scope["protocolMappers"] if x["id"] != m.group(2)
            ]
            return None

        if route == "/clients" and method == "GET":
            reps = [self.client_rep(c) for c in self.clients.values()]
            if "clientId" in query:
                reps = [r for r in reps if r["clientId"] == query["clientId"][0]]
            return reps
        if route == "/clients" and method == "POST":
            self._add_client(body)
            return None
        m = re.fullmatch(r"/clients/([^/]+)", route)
        if m and method == "PUT":
            client = self.clients[m.group(1)]
            for key, value in body.items():
                if key == "attributes":
                    # Keycloak keeps an attribute the body leaves out and removes one it
                    # sends as an empty string (checked against 26.7.0).
                    attributes = client.setdefault("attributes", {})
                    attributes.update(copy.deepcopy(value or {}))
                    client["attributes"] = {k: v for k, v in attributes.items() if v != ""}
                elif key not in ("defaultClientScopes", "optionalClientScopes", "id"):
                    client[key] = copy.deepcopy(value)
            if client.get("serviceAccountsEnabled") and "_service_user" not in client:
                self._add_service_user(client)
            elif not client.get("serviceAccountsEnabled") and "_service_user" in client:
                del self.users[client.pop("_service_user")]
            return None
        if m and method == "DELETE":
            client = self.clients.pop(m.group(1))
            if "_service_user" in client:
                del self.users[client["_service_user"]]
            return None
        if route == "/events/config":
            if method == "GET":
                return copy.deepcopy(self.events_config)
            self.events_config = copy.deepcopy(body)
            return None
        if route == "/events" and method == "GET":
            rows = [
                e
                for e in self.events
                if e["clientId"] == query.get("client", [e["clientId"]])[0]
                and e["type"] in query.get("type", [e["type"]])
            ]
            return copy.deepcopy(rows[: int(query.get("max", ["100"])[0])])
        m = re.fullmatch(r"/clients/([^/]+)/protocol-mappers/models", route)
        if m and method == "POST":
            self.clients[m.group(1)]["protocolMappers"].append(dict(body, id=self._id("mapper")))
            return None
        m = re.fullmatch(r"/clients/([^/]+)/protocol-mappers/models/([^/]+)", route)
        if m and method == "DELETE":
            client = self.clients[m.group(1)]
            client["protocolMappers"] = [
                x for x in client["protocolMappers"] if x["id"] != m.group(2)
            ]
            return None
        m = re.fullmatch(r"/clients/([^/]+)/roles", route)
        if m and method == "GET":
            client = self.clients[m.group(1)]
            return [self._client_role(client, n) for n in sorted(client.get("_roles", {}))]
        m = re.fullmatch(r"/clients/([^/]+)/roles/([^/]+)", route)
        if m and method == "GET":
            return self._client_role(self.clients[m.group(1)], urllib.parse.unquote(m.group(2)))
        m = re.fullmatch(r"/clients/([^/]+)/service-account-user", route)
        if m and method == "GET":
            uid = self.clients[m.group(1)].get("_service_user")
            if uid is None:
                raise NotFound(path)
            return {"id": uid, "username": self.users[uid]["username"]}
        m = re.fullmatch(r"/clients/([^/]+)/scope-mappings", route)
        if m and method == "GET":
            client = self.clients[m.group(1)]
            return self._mappings(client["_role_scope"], client["_client_scope"])
        m = re.fullmatch(r"/clients/([^/]+)/scope-mappings/clients/([^/]+)", route)
        if m:
            held = self.clients[m.group(1)]["_client_scope"].setdefault(m.group(2), set())
            return self._map(held, self.clients[m.group(2)], method, body)
        if route == "/users" and method == "GET":
            # Keycloak leaves service-account users out of the user list.
            people = [u for u in self.users.values() if "serviceAccountClientLink" not in u]
            first = int(query.get("first", ["0"])[0])
            count = int(query.get("max", ["100"])[0])
            return [
                {k: v for k, v in u.items() if not k.startswith("_")}
                for u in people[first : first + count]
            ]
        m = re.fullmatch(r"/users/([^/]+)", route)
        if m and method == "DELETE":
            if self.users.pop(m.group(1), None) is None:
                raise NotFound(path)
            return None
        m = re.fullmatch(r"/users/([^/]+)/role-mappings/realm/composite", route)
        if m and method == "GET":
            user = self.users[m.group(1)]
            return [self._role_rep(n) for n in sorted(self._effective_realm(user))]
        m = re.fullmatch(r"/users/([^/]+)/role-mappings", route)
        if m and method == "GET":
            user = self.users[m.group(1)]
            return self._mappings(user["_realm"], user["_clients"])
        m = re.fullmatch(r"/users/([^/]+)/groups", route)
        if m and method == "GET":
            user = self.users[m.group(1)]
            return [
                {k: v for k, v in self.groups[g].items() if not k.startswith("_")}
                for g in sorted(user["_groups"])
            ]
        m = re.fullmatch(r"/users/([^/]+)/groups/([^/]+)", route)
        if m:
            user = self.users[m.group(1)]
            if m.group(2) not in self.groups:
                raise NotFound(path)
            if method == "PUT":
                user["_groups"].add(m.group(2))
            elif method == "DELETE":
                user["_groups"].discard(m.group(2))
            return None
        m = re.fullmatch(r"/users/([^/]+)/role-mappings/realm", route)
        if m:
            user = self.users[m.group(1)]
            if method == "GET":
                return [self._role_rep(n) for n in sorted(user["_realm"])]
            names = {r["name"] for r in body}
            if method == "POST":
                user["_realm"] |= names
            elif method == "DELETE":
                user["_realm"] -= names
            return None
        m = re.fullmatch(r"/users/([^/]+)/role-mappings/clients/([^/]+)", route)
        if m:
            held = self.users[m.group(1)]["_clients"].setdefault(m.group(2), set())
            return self._map(held, self.clients[m.group(2)], method, body)
        m = re.fullmatch(r"/clients/([^/]+)/(default|optional)-client-scopes/([^/]+)", route)
        if m:
            client, kind, sid = self.clients[m.group(1)], f"_{m.group(2)}", m.group(3)
            if sid not in self.scopes:
                raise NotFound(path)
            if method == "PUT" and sid not in client[kind]:
                client[kind].append(sid)
            elif method == "DELETE" and sid in client[kind]:
                client[kind].remove(sid)
            return None
        m = re.fullmatch(r"/clients/([^/]+)/scope-mappings/realm", route)
        if m:
            client = self.clients[m.group(1)]
            if method == "GET":
                return [self._role_rep(n) for n in sorted(client["_role_scope"])]
            names = {r["name"] for r in body}
            if method == "POST":
                client["_role_scope"] |= names
            elif method == "DELETE":
                client["_role_scope"] -= names
            return None

        if route == "/client-policies/profiles":
            if method == "GET":
                return {"profiles": copy.deepcopy(self.profiles)}
            if method == "PUT":
                self.profiles = copy.deepcopy(body["profiles"])
                return None
        if route == "/client-policies/policies":
            if method == "GET":
                return {"policies": copy.deepcopy(self.policies)}
            if method == "PUT":
                self._check_policies(body["policies"])
                self.policies = copy.deepcopy(body["policies"])
                return None

        m = re.fullmatch(r"/default-(optional|default)-client-scopes(?:/([^/]+))?", route)
        if m:
            target = self.default_optional if m.group(1) == "optional" else self.default_default
            if method == "GET":
                return [{"id": i, "name": self.scopes[i]["name"]} for i in target]
            if method == "DELETE" and m.group(2) in target:
                target.remove(m.group(2))
            return None
        raise AssertionError(f"unexpected call {method} {path}")
