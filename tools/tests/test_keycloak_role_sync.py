from __future__ import annotations

import io
import json
import re
import urllib.error

import pytest

from lib import keycloak_role_sync as kcs


def _realm_def() -> dict:
    return {
        "roles": {
            "realm": [
                {
                    "name": "papaia-admin",
                    "description": "Full administrator access",
                    "composite": True,
                    "composites": {"realm": ["librechat-admin", "litellm-admin"]},
                },
                {
                    "name": "librechat-admin",
                    "description": "LibreChat administrator",
                    "composite": True,
                    "composites": {"realm": ["librechat-user"]},
                },
                {"name": "librechat-user", "description": "LibreChat login"},
                {"name": "litellm-admin", "description": "LiteLLM administrator"},
                {"name": "user", "description": "Regular user"},
            ]
        },
        "clients": [
            {
                "clientId": "oauth2-proxy",
                "protocolMappers": [
                    {
                        "name": "realm-roles",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-realm-role-mapper",
                        "config": {"claim.name": "roles"},
                    },
                    {
                        "name": "realm-roles-as-groups",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-realm-role-mapper",
                        "config": {"claim.name": "groups"},
                    },
                ],
            }
        ],
    }


class FakeKeycloak:
    """Minimal in-memory stand-in for the parts of the Admin REST API this
    module touches, driven through the same (method, path, body) shape as
    the real `_api()` so the sync functions are exercised unmodified."""

    def __init__(self, *, roles=None, clients=None, users=None, realm=None):
        # The realm representation GET/PUT on the realm itself answer with: only the
        # settings the sync touches. A PUT replaces whatever keys it carries, as Keycloak does.
        self.realm: dict = realm if realm is not None else {
            "smtpServer": {},
            "resetPasswordAllowed": False,
        }
        self.realm_puts: list[dict] = []
        # role name -> {"id", "name", "description", "composite", "composites": set()}
        self.roles: dict[str, dict] = roles or {}
        # client uuid -> {"clientId", "mappers": {name: mapper}, "roles": {role names}}
        self.clients: dict[str, dict] = clients or {}
        # user id -> {"username", "roles": set()}
        self.users: dict[str, dict] = users or {}
        self.secret_reads = 0

    def _role_rep(self, name: str) -> dict:
        r = self.roles[name]
        return {
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "composite": r["composite"],
        }

    def _client_role_rep(self, uuid: str, name: str) -> dict:
        return {
            "id": f"{uuid}-{name}",
            "name": name,
            "clientRole": True,
            "containerId": uuid,
            "composite": False,
        }

    def _composite_reps(self, name: str) -> list[dict]:
        """What GET /roles/<name>/composites answers: realm and client roles, told apart by
        `clientRole` and `containerId`, as Keycloak does."""
        reps = []
        for member in self.roles[name].get("composites", set()):
            if isinstance(member, tuple):
                reps.append(self._client_role_rep(*member))
            else:
                reps.append(self._role_rep(member))
        return reps

    def __call__(self, base_url, ctx, token, method, path, body=None):
        if path == "" and method == "GET":
            return json.loads(json.dumps(self.realm))
        if path == "" and method == "PUT":
            self.realm_puts.append(json.loads(json.dumps(body)))
            self.realm.update(json.loads(json.dumps(body)))
            return None

        if path == "/roles" and method == "GET":
            return [self._role_rep(n) for n in self.roles]
        if path == "/roles" and method == "POST":
            name = body["name"]
            self.roles[name] = {
                "id": f"role-{name}",
                "name": name,
                "description": body.get("description", ""),
                "composite": body.get("composite", False),
                "composites": set(),
            }
            return None

        m = re.fullmatch(r"/roles/([^/]+)", path)
        if m and method == "GET":
            return self._role_rep(m.group(1))

        m = re.fullmatch(r"/roles/([^/]+)/composites", path)
        if m and method == "GET":
            return self._composite_reps(m.group(1))
        if m and method == "POST":
            name = m.group(1)
            for rep in body:
                member = (rep["containerId"], rep["name"]) if rep.get("clientRole") else rep["name"]
                self.roles[name].setdefault("composites", set()).add(member)
            return None

        m = re.fullmatch(r"/roles/([^/]+)/users", path)
        if m and method == "GET":
            name = m.group(1)
            return [
                {"id": uid, "username": u["username"]}
                for uid, u in self.users.items()
                if name in u["roles"]
            ]

        if path == "/clients" and method == "POST":
            uuid = f"uuid-{body['clientId']}"
            self.clients[uuid] = {
                "clientId": body["clientId"],
                "mappers": {mp["name"]: mp for mp in body.get("protocolMappers", [])},
                "created_from": body,
            }
            return None

        m = re.fullmatch(r"/clients/([^/]+)/roles/([^/]+)", path)
        if m and method == "GET":
            uuid, name = m.groups()
            if name not in self.clients[uuid].get("roles", set()):
                raise urllib.error.HTTPError(
                    f"https://localhost:8110/clients/{uuid}/roles/{name}",
                    404,
                    "Not Found",
                    {},
                    io.BytesIO(b'{"error":"Could not find role"}'),
                )
            return self._client_role_rep(uuid, name)

        m = re.fullmatch(r"/clients/([^/]+)/client-secret", path)
        if m and method == "GET":
            self.secret_reads += 1
            return {"type": "secret", "value": self.clients[m.group(1)].get("secret")}

        m = re.fullmatch(r"/clients/([^/]+)", path)
        if m and method == "PUT":
            client = self.clients[m.group(1)]
            client.setdefault("put_bodies", []).append(body)
            if "secret" in body:
                client["secret"] = body["secret"]
            return None

        m = re.fullmatch(r"/clients\?clientId=([^&]+)", path)
        if m and method == "GET":
            client_id = m.group(1)
            return [
                {"id": uuid, "clientId": c["clientId"]}
                for uuid, c in self.clients.items()
                if c["clientId"] == client_id
            ]

        m = re.fullmatch(r"/clients/([^/]+)/protocol-mappers/models", path)
        if m and method == "GET":
            uuid = m.group(1)
            return list(self.clients[uuid]["mappers"].values())
        if m and method == "POST":
            uuid = m.group(1)
            self.clients[uuid]["mappers"][body["name"]] = body
            return None

        m = re.fullmatch(r"/users/([^/]+)/role-mappings/realm", path)
        if m and method == "GET":
            uid = m.group(1)
            return [{"name": n} for n in self.users[uid]["roles"]]
        if m and method == "POST":
            uid = m.group(1)
            for rep in body:
                self.users[uid]["roles"].add(rep["name"])
            return None

        raise AssertionError(f"unhandled fake API call: {method} {path}")


def _role(name: str, *, composite: bool = False) -> dict:
    return {
        "id": f"role-{name}",
        "name": name,
        "description": "",
        "composite": composite,
        "composites": set(),
    }


def _patch_common(monkeypatch, fake: FakeKeycloak):
    monkeypatch.setattr(kcs, "_wait_for_keycloak", lambda base_url, ctx, timeout=90: None)
    monkeypatch.setattr(kcs, "_get_admin_token", lambda base_url, ctx, password: "fake-token")
    monkeypatch.setattr(kcs, "_api", fake)


def _tree() -> dict[str, dict[str, str]]:
    return {
        "": {"AUTH_PROVIDER": "internal_keycloak", "KEYCLOAK_EXT_PORT": "8110"},
        "infra/keycloak": {"KC_ADMIN_PASSWORD": "correct-password"},
    }


def test_sync_noop_when_not_internal_keycloak():
    tree = {"": {"AUTH_PROVIDER": "external_oidc"}}
    # No password, no config dir realm file -- would raise/fail if it tried
    # to do anything, so success here proves it skipped everything.
    assert kcs.sync_roles(tree, config_dir=None) is True


def test_sync_raises_when_password_missing():
    tree = {"": {"AUTH_PROVIDER": "internal_keycloak"}, "infra/keycloak": {}}
    with pytest.raises(RuntimeError, match="KC_ADMIN_PASSWORD"):
        kcs.sync_roles(tree, config_dir=None)


def test_sync_raises_when_password_is_placeholder():
    tree = {
        "": {"AUTH_PROVIDER": "internal_keycloak"},
        "infra/keycloak": {"KC_ADMIN_PASSWORD": "GENERATE_KC_ADMIN_PASSWORD"},
    }
    with pytest.raises(RuntimeError, match="KC_ADMIN_PASSWORD"):
        kcs.sync_roles(tree, config_dir=None)


def test_sync_returns_false_when_realm_json_missing(tmp_path):
    result = kcs.sync_roles(_tree(), config_dir=tmp_path)
    assert result is False


def test_sync_returns_false_on_timeout(tmp_path, monkeypatch, capsys):
    _write_realm_json(tmp_path, _realm_def())

    def _fake_wait(base_url, ctx, timeout=90):
        raise TimeoutError(f"Keycloak at {base_url} did not become ready within {timeout}s")

    monkeypatch.setattr(kcs, "_wait_for_keycloak", _fake_wait)
    result = kcs.sync_roles(_tree(), config_dir=tmp_path)
    assert result is False
    assert "Keycloak" in capsys.readouterr().err


def _write_realm_json(config_dir, realm_def: dict) -> None:
    path = config_dir / "infra" / "keycloak" / "realm-import" / "papaia-realm.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(realm_def), encoding="utf-8")


def test_sync_creates_missing_roles_and_composites_and_mapper(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _realm_def())
    fake = FakeKeycloak(
        roles={"user": _role("user")},
        clients={
            "uuid-oauth2-proxy": {
                "clientId": "oauth2-proxy",
                "mappers": {
                    "realm-roles": {
                        "name": "realm-roles",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-realm-role-mapper",
                        "config": {"claim.name": "roles"},
                    },
                },
            }
        },
    )
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    expected_roles = {"user", "papaia-admin", "librechat-admin", "litellm-admin", "librechat-user"}
    assert set(fake.roles) == expected_roles
    assert fake.roles["papaia-admin"]["composites"] == {"librechat-admin", "litellm-admin"}
    assert fake.roles["librechat-admin"]["composites"] == {"librechat-user"}
    assert "realm-roles-as-groups" in fake.clients["uuid-oauth2-proxy"]["mappers"]


def test_sync_migrates_legacy_admin_users_without_touching_the_role(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _realm_def())
    fake = FakeKeycloak(
        roles={
            "admin": _role("admin"),
            "papaia-admin": _role("papaia-admin", composite=True),
            "librechat-admin": _role("librechat-admin", composite=True),
            "librechat-user": _role("librechat-user"),
            "litellm-admin": _role("litellm-admin"),
            "user": _role("user"),
        },
        clients={"uuid-oauth2-proxy": {"clientId": "oauth2-proxy", "mappers": {}}},
        users={
            "u1": {"username": "admin", "roles": {"admin", "user"}},
            "u2": {"username": "someone-else", "roles": {"user"}},
        },
    )
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    assert "papaia-admin" in fake.users["u1"]["roles"]
    assert "admin" in fake.users["u1"]["roles"], "the legacy role must not be removed"
    assert "papaia-admin" not in fake.users["u2"]["roles"]

    # Idempotent: running again must not re-grant or error.
    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True
    assert fake.users["u1"]["roles"] == {"admin", "user", "papaia-admin"}


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("secret", "secret"),
        ("secret   # Change this! Used only on first start.", "secret"),
        ("secret # note", "secret"),
        ("pass#word", "pass#word"),
        ('"quoted pw"  # note', "quoted pw"),
        ("'single'", "single"),
        ("", ""),
    ],
)
def test_compose_value_matches_docker_compose_inline_comment_handling(raw, expected):
    assert kcs._compose_value(raw) == expected


def test_sync_sends_the_password_without_its_inline_comment(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _realm_def())
    sent = {}

    def _capture(base_url, ctx, password):
        sent["password"] = password
        return "fake-token"

    fake = FakeKeycloak(roles={"user": _role("user")})
    _patch_common(monkeypatch, fake)
    monkeypatch.setattr(kcs, "_get_admin_token", _capture)
    tree = _tree()
    tree["infra/keycloak"]["KC_ADMIN_PASSWORD"] = "correct-password   # First start only."

    assert kcs.sync_roles(tree, config_dir=tmp_path) is True
    assert sent["password"] == "correct-password"


def _http_error(code: int, body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://localhost:8110/x", code, "Bad Request", {}, io.BytesIO(body)
    )


def test_sync_returns_false_with_a_hint_when_admin_login_is_rejected(
    tmp_path, monkeypatch, capsys
):
    _write_realm_json(tmp_path, _realm_def())
    monkeypatch.setattr(kcs, "_wait_for_keycloak", lambda base_url, ctx, timeout=90: None)

    def _reject(base_url, ctx, password):
        raise _http_error(400, b'{"error_description":"Invalid user credentials"}')

    monkeypatch.setattr(kcs, "_get_admin_token", _reject)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is False
    err = capsys.readouterr().err
    assert "Invalid user credentials" in err
    assert "KC_ADMIN_PASSWORD" in err


def test_sync_returns_false_when_an_api_call_fails_midway(tmp_path, monkeypatch, capsys):
    _write_realm_json(tmp_path, _realm_def())
    monkeypatch.setattr(kcs, "_wait_for_keycloak", lambda base_url, ctx, timeout=90: None)
    monkeypatch.setattr(kcs, "_get_admin_token", lambda base_url, ctx, password: "fake-token")

    def _boom(*args, **kwargs):
        raise _http_error(403, b"forbidden")

    monkeypatch.setattr(kcs, "_api", _boom)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is False
    assert "HTTP 403" in capsys.readouterr().err


_USER_RIGHTS = ["manage-users", "view-users", "query-users", "view-realm", "manage-realm"]


def _realm_def_with_user_rights() -> dict:
    """The realm definition with `papaia-admin` carrying the realm-management roles."""
    realm_def = _realm_def()
    realm_def["roles"]["realm"][0]["composites"]["client"] = {"realm-management": _USER_RIGHTS}
    return realm_def


def _realm_management(*roles: str) -> dict:
    return {
        "uuid-realm-management": {
            "clientId": "realm-management",
            "mappers": {},
            "roles": set(roles),
        },
        "uuid-oauth2-proxy": {"clientId": "oauth2-proxy", "mappers": {}},
    }


def _existing_realm(**more) -> FakeKeycloak:
    """A realm that predates the user rights: every role of the template is there."""
    return FakeKeycloak(
        roles={
            "papaia-admin": _role("papaia-admin", composite=True),
            "librechat-admin": _role("librechat-admin", composite=True),
            "librechat-user": _role("librechat-user"),
            "litellm-admin": _role("litellm-admin"),
            "user": _role("user"),
        },
        **more,
    )


def test_sync_adds_the_client_role_composites_to_an_existing_realm(tmp_path, monkeypatch, capsys):
    _write_realm_json(tmp_path, _realm_def_with_user_rights())
    fake = _existing_realm(clients=_realm_management(*_USER_RIGHTS))
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    members = fake.roles["papaia-admin"]["composites"]
    assert {m for m in members if isinstance(m, tuple)} == {
        ("uuid-realm-management", right) for right in _USER_RIGHTS
    }
    assert {m for m in members if isinstance(m, str)} == {"librechat-admin", "litellm-admin"}
    out = capsys.readouterr().out
    assert "realm-management/manage-users" in out
    assert "8 composite edge(s) added" in out


def test_sync_adds_nothing_the_second_time(tmp_path, monkeypatch, capsys):
    _write_realm_json(tmp_path, _realm_def_with_user_rights())
    fake = _existing_realm(clients=_realm_management(*_USER_RIGHTS))
    _patch_common(monkeypatch, fake)
    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True
    before = set(fake.roles["papaia-admin"]["composites"])
    capsys.readouterr()

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    assert fake.roles["papaia-admin"]["composites"] == before
    assert "0 composite edge(s) added" in capsys.readouterr().out


def test_sync_adds_only_the_client_roles_a_role_lacks(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _realm_def_with_user_rights())
    fake = _existing_realm(clients=_realm_management(*_USER_RIGHTS))
    fake.roles["papaia-admin"]["composites"] = {
        "librechat-admin",
        "litellm-admin",
        ("uuid-realm-management", "view-realm"),
    }
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    assert fake.roles["papaia-admin"]["composites"] == {
        "librechat-admin",
        "litellm-admin",
        *{("uuid-realm-management", right) for right in _USER_RIGHTS},
    }


def test_sync_keeps_a_member_the_template_does_not_name(tmp_path, monkeypatch):
    # Additive only: an operator's own composite member is never removed.
    _write_realm_json(tmp_path, _realm_def_with_user_rights())
    fake = _existing_realm(clients=_realm_management(*_USER_RIGHTS))
    fake.roles["papaia-admin"]["composites"] = {"user", ("uuid-realm-management", "manage-clients")}
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    members = fake.roles["papaia-admin"]["composites"]
    assert "user" in members and ("uuid-realm-management", "manage-clients") in members


def test_a_realm_role_of_the_same_name_does_not_stand_in_for_the_client_role(
    tmp_path, monkeypatch
):
    _write_realm_json(tmp_path, _realm_def_with_user_rights())
    fake = _existing_realm(clients=_realm_management(*_USER_RIGHTS))
    fake.roles["view-users"] = _role("view-users")
    fake.roles["papaia-admin"]["composites"] = {"view-users"}  # a realm role, not the client's
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    assert ("uuid-realm-management", "view-users") in fake.roles["papaia-admin"]["composites"]


def test_sync_warns_and_carries_on_when_the_client_is_missing(tmp_path, monkeypatch, capsys):
    _write_realm_json(tmp_path, _realm_def_with_user_rights())
    only_oauth2_proxy = {"uuid-oauth2-proxy": {"clientId": "oauth2-proxy", "mappers": {}}}
    fake = _existing_realm(clients=only_oauth2_proxy)
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    captured = capsys.readouterr()
    assert "client realm-management not found" in captured.err
    # The realm composites, the clients and the mappers after it still ran.
    assert fake.roles["papaia-admin"]["composites"] == {"librechat-admin", "litellm-admin"}
    assert "realm-roles-as-groups" in fake.clients["uuid-oauth2-proxy"]["mappers"]
    assert "3 composite edge(s) added" in captured.out


def test_sync_warns_and_carries_on_when_the_client_lacks_a_role(tmp_path, monkeypatch, capsys):
    _write_realm_json(tmp_path, _realm_def_with_user_rights())
    fake = _existing_realm(clients=_realm_management("manage-users", "view-users", "query-users"))
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    assert "has no role view-realm" in capsys.readouterr().err
    members = fake.roles["papaia-admin"]["composites"]
    assert ("uuid-realm-management", "manage-users") in members
    assert ("uuid-realm-management", "view-realm") not in members


# What the template ships, read from the real file: the sync can only apply what is there.
def _template_realm() -> dict:
    import re
    from pathlib import Path

    template = Path(__file__).resolve().parents[2] / "src/infra/keycloak/realm-import"
    raw = (template / "papaia-realm.json.template").read_text(encoding="utf-8")
    return json.loads(re.sub(r"\$\{env\.([^}]+)\}", r"secret-of-\1", raw))


def test_the_template_gives_papaia_admin_the_user_rights_and_nobody_else():
    roles = {r["name"]: r for r in _template_realm()["roles"]["realm"]}
    assert roles["papaia-admin"]["composites"]["client"] == {"realm-management": _USER_RIGHTS}
    others = {n: r for n, r in roles.items() if n != "papaia-admin"}
    assert not [n for n, r in others.items() if r.get("composites", {}).get("client")], (
        "only papaia-admin may carry Keycloak's user-administration rights"
    )
    assert "manager-admin" in roles["papaia-admin"]["composites"]["realm"]
    assert "composites" not in roles["manager-admin"]



@pytest.fixture(autouse=True)
def _confidential_profile_client(monkeypatch):
    """The clients the rag profile ships today are all resource servers without a secret.
    The secret handling of the sync is generic, so it is exercised with a stand-in
    confidential client that the profile is made to ask for."""
    monkeypatch.setitem(
        kcs.PROFILE_CLIENTS, "rag", (*kcs.PROFILE_CLIENTS["rag"], "rag-confidential-client")
    )


def _rag_realm_def(*, secret: str = "baked-secret") -> dict:
    audience_mapper = {
        "name": "mcp-qdrant-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {"included.client.audience": "mcp-qdrant"},
    }
    return {
        "roles": {"realm": [{"name": "qdrant-ingest-operator", "description": "Operator"}]},
        "clients": [
            {"clientId": "librechat", "protocolMappers": [audience_mapper]},
            {"clientId": "mcp-qdrant", "bearerOnly": False, "publicClient": False},
            {
                "clientId": "rag-confidential-client",
                "clientAuthenticatorType": "client-secret",
                "secret": secret,
            },
            {
                "clientId": "papaia-manager",
                "clientAuthenticatorType": "client-secret",
                "secret": "manager-secret",
            },
        ],
    }


def _rag_tree(profiles: str) -> dict[str, dict[str, str]]:
    tree = _tree()
    tree[""]["COMPOSE_PROFILES"] = profiles
    return tree


def _librechat_client() -> dict:
    return {"uuid-librechat": {"clientId": "librechat", "mappers": {}}}


def test_sync_creates_the_rag_clients_only_while_the_profile_is_active(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _rag_realm_def())
    fake = FakeKeycloak(roles={}, clients=_librechat_client())
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("keycloak,librechat,rag"), config_dir=tmp_path) is True

    created = {c["clientId"] for c in fake.clients.values()}
    assert created == {"librechat", "mcp-qdrant", "rag-confidential-client"}
    assert fake.clients["uuid-rag-confidential-client"]["created_from"]["secret"] == "baked-secret"
    # Clients come before mappers, so the audience mapper lands on librechat too.
    assert "mcp-qdrant-audience" in fake.clients["uuid-librechat"]["mappers"]


def test_sync_leaves_the_realm_without_rag_clients_when_the_profile_is_off(
    tmp_path, monkeypatch
):
    _write_realm_json(tmp_path, _rag_realm_def())
    fake = FakeKeycloak(roles={}, clients=_librechat_client())
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("keycloak,librechat"), config_dir=tmp_path) is True

    assert {c["clientId"] for c in fake.clients.values()} == {"librechat"}


def test_sync_creates_only_clients_a_profile_asks_for(tmp_path, monkeypatch):
    # papaia-manager is in the template but belongs to no entry of PROFILE_CLIENTS,
    # so enabling the rag profile must not pull it in.
    _write_realm_json(tmp_path, _rag_realm_def())
    fake = FakeKeycloak(roles={}, clients=_librechat_client())
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("rag,manager"), config_dir=tmp_path) is True

    assert "papaia-manager" not in {c["clientId"] for c in fake.clients.values()}


def _existing_confidential(secret=None, **extra) -> dict:
    client = {"clientId": "rag-confidential-client", "mappers": {}, **extra}
    if secret is not None:
        client["secret"] = secret
    return {"uuid-ui": client, **_librechat_client()}


def _confidential_clients(fake: FakeKeycloak) -> list[dict]:
    return [c for c in fake.clients.values() if c["clientId"] == "rag-confidential-client"]


def test_an_existing_client_keeps_everything_but_its_secret(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _rag_realm_def())
    clients = _existing_confidential("secret-from-the-addon", rotated=True)
    fake = FakeKeycloak(roles={}, clients=clients)
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("rag"), config_dir=tmp_path) is True

    (ui,) = _confidential_clients(fake)
    assert ui.get("rotated") is True, "the rest of the client is not touched"
    assert "created_from" not in ui, "it is not recreated"
    assert ui["put_bodies"] == [{"secret": "baked-secret"}], "only the secret is written"


def test_a_secret_left_over_from_an_earlier_install_is_aligned_once(
    tmp_path, monkeypatch, capsys
):
    """The add-on's client already exists with the secret it was created with; the
    service signs in with the one setup generated and Keycloak answers 401."""
    _write_realm_json(tmp_path, _rag_realm_def())
    fake = FakeKeycloak(roles={}, clients=_existing_confidential("secret-from-the-addon"))
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("rag"), config_dir=tmp_path) is True
    first = capsys.readouterr().out
    assert kcs.sync_roles(_rag_tree("rag"), config_dir=tmp_path) is True
    second = capsys.readouterr().out

    (ui,) = _confidential_clients(fake)
    assert ui["secret"] == "baked-secret"
    assert len(ui["put_bodies"]) == 1, "the second run finds nothing to change"
    assert "client secret updated: rag-confidential-client" in first
    assert "1 client secret(s) updated" in first
    assert "client secret updated" not in second
    assert "0 client secret(s) updated" in second


def test_a_secret_that_already_matches_is_not_written(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _rag_realm_def())
    fake = FakeKeycloak(roles={}, clients=_existing_confidential("baked-secret"))
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("rag"), config_dir=tmp_path) is True

    assert "put_bodies" not in _confidential_clients(fake)[0]


def test_a_placeholder_never_replaces_the_secret_of_an_existing_client(tmp_path, monkeypatch):
    placeholder = "GENERATE_KC_RAG_CONFIDENTIAL_CLIENT_SECRET"
    _write_realm_json(tmp_path, _rag_realm_def(secret=placeholder))
    fake = FakeKeycloak(roles={}, clients=_existing_confidential("working-secret"))
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("rag"), config_dir=tmp_path) is True

    (ui,) = _confidential_clients(fake)
    assert ui["secret"] == "working-secret"
    assert "put_bodies" not in ui


def test_a_resource_server_client_is_not_asked_for_a_secret(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _rag_realm_def())
    clients = {
        "uuid-mcp": {"clientId": "mcp-qdrant", "mappers": {}},
        **_existing_confidential("baked-secret"),
    }
    fake = FakeKeycloak(roles={}, clients=clients)
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("rag"), config_dir=tmp_path) is True

    assert fake.secret_reads == 1, "only the confidential client is read"
    assert "put_bodies" not in clients["uuid-mcp"]


def test_no_secret_is_touched_while_the_profile_is_off(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _rag_realm_def())
    fake = FakeKeycloak(roles={}, clients=_existing_confidential("secret-from-the-addon"))
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("keycloak,librechat"), config_dir=tmp_path) is True

    assert _confidential_clients(fake)[0]["secret"] == "secret-from-the-addon"
    assert fake.secret_reads == 0


def test_sync_skips_a_client_whose_secret_is_still_a_placeholder(tmp_path, monkeypatch, capsys):
    placeholder = "GENERATE_KC_RAG_CONFIDENTIAL_CLIENT_SECRET"
    _write_realm_json(tmp_path, _rag_realm_def(secret=placeholder))
    fake = FakeKeycloak(roles={}, clients=_librechat_client())
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_rag_tree("rag"), config_dir=tmp_path) is True

    created = {c["clientId"] for c in fake.clients.values()}
    assert "rag-confidential-client" not in created, "a placeholder must never become a real secret"
    assert "mcp-qdrant" in created
    assert "rag-confidential-client" in capsys.readouterr().err


# ── the realm's mail server (profile smtp) ────────────────────────────────────

RELAY_BLOCK = {
    "host": "smtp-relay",
    "port": "587",
    "from": "noreply@example.org",
    "fromDisplayName": "papAIa",
    "auth": "false",
    "ssl": "false",
    "starttls": "false",
}


def _smtp_realm_def(*, on: bool = True) -> dict:
    """The rendered realm: with the relay block while the profile is on, without otherwise."""
    realm = _realm_def()
    if on:
        realm["smtpServer"] = dict(RELAY_BLOCK)
        realm["resetPasswordAllowed"] = True
    return realm


def _smtp_fake(*, smtp_server=None, reset_allowed=False) -> FakeKeycloak:
    return FakeKeycloak(
        roles={"user": _role("user")},
        clients={"uuid-oauth2-proxy": {"clientId": "oauth2-proxy", "mappers": {}}},
        realm={"smtpServer": smtp_server or {}, "resetPasswordAllowed": reset_allowed},
    )


def _run_smtp_sync(tmp_path, monkeypatch, realm_def: dict, fake: FakeKeycloak) -> None:
    _write_realm_json(tmp_path, realm_def)
    _patch_common(monkeypatch, fake)
    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True


def test_a_realm_without_a_mail_server_gets_the_relay_and_the_reset_link(tmp_path, monkeypatch):
    fake = _smtp_fake()

    _run_smtp_sync(tmp_path, monkeypatch, _smtp_realm_def(), fake)

    assert fake.realm["smtpServer"] == RELAY_BLOCK
    assert fake.realm["resetPasswordAllowed"] is True
    assert len(fake.realm_puts) == 1
    assert "password" not in fake.realm["smtpServer"], "the relay needs no login"


def test_the_relay_block_is_written_once(tmp_path, monkeypatch):
    fake = _smtp_fake()
    _write_realm_json(tmp_path, _smtp_realm_def())
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True
    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    assert len(fake.realm_puts) == 1


def test_a_stale_relay_block_is_corrected_and_the_rest_of_it_is_kept(tmp_path, monkeypatch):
    stale = {
        **RELAY_BLOCK,
        "port": "25",
        "from": "old@example.org",
        "auth": "true",
        "user": "leftover",
        "password": "**********",  # Keycloak masks a stored password on read
        "replyTo": "reply@example.org",
    }
    fake = _smtp_fake(smtp_server=stale)

    _run_smtp_sync(tmp_path, monkeypatch, _smtp_realm_def(), fake)

    assert fake.realm["smtpServer"] == {**RELAY_BLOCK, "replyTo": "reply@example.org"}
    assert set(fake.realm_puts[-1]) == {"smtpServer"}, "the reset link is not part of this update"
    assert fake.realm["resetPasswordAllowed"] is False


def test_an_admin_who_turned_the_reset_link_off_is_not_overruled(tmp_path, monkeypatch):
    fake = _smtp_fake(smtp_server=dict(RELAY_BLOCK), reset_allowed=False)

    _run_smtp_sync(tmp_path, monkeypatch, _smtp_realm_def(), fake)

    assert fake.realm_puts == []


def test_a_hand_configured_mail_server_is_left_alone(tmp_path, monkeypatch, capsys):
    own = {
        "host": "mail.example.com",
        "port": "587",
        "auth": "true",
        "user": "keycloak",
        "password": "**********",
    }
    fake = _smtp_fake(smtp_server=dict(own))

    _run_smtp_sync(tmp_path, monkeypatch, _smtp_realm_def(), fake)

    assert fake.realm_puts == []
    assert fake.realm["smtpServer"] == own
    assert "mail.example.com" in capsys.readouterr().err


def test_switching_the_profile_off_clears_the_relay_block(tmp_path, monkeypatch):
    fake = _smtp_fake(smtp_server=dict(RELAY_BLOCK), reset_allowed=True)

    _run_smtp_sync(tmp_path, monkeypatch, _smtp_realm_def(on=False), fake)

    assert fake.realm["smtpServer"] == {}
    assert fake.realm["resetPasswordAllowed"] is False


def test_switching_the_profile_off_leaves_a_hand_configured_mail_server(tmp_path, monkeypatch):
    fake = _smtp_fake(smtp_server={"host": "mail.example.com", "port": "587"}, reset_allowed=True)

    _run_smtp_sync(tmp_path, monkeypatch, _smtp_realm_def(on=False), fake)

    assert fake.realm_puts == []


def test_a_realm_without_smtp_and_without_the_profile_is_untouched(tmp_path, monkeypatch):
    # The operator opened the reset link for their own reasons.
    fake = _smtp_fake(reset_allowed=True)

    _run_smtp_sync(tmp_path, monkeypatch, _smtp_realm_def(on=False), fake)

    assert fake.realm_puts == []
    assert fake.realm["resetPasswordAllowed"] is True
