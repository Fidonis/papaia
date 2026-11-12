from __future__ import annotations

import io
import json
import re
import ssl
import urllib.error

import pytest
import yaml

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
        if m and method == "GET":
            client = self.clients[m.group(1)]
            return {
                "id": m.group(1),
                "clientId": client["clientId"],
                "attributes": dict(client.get("attributes", {})),
            }
        if m and method == "PUT":
            client = self.clients[m.group(1)]
            client.setdefault("put_bodies", []).append(body)
            if "secret" in body:
                client["secret"] = body["secret"]
            if "attributes" in body:
                # Keycloak replaces the whole attribute map.
                client["attributes"] = dict(body["attributes"])
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


# ---------------------------------------------------------------------------
# Where the sync reaches Keycloak
# ---------------------------------------------------------------------------

_INTERNAL_TOKEN_URL = "https://keycloak:8443/realms/papaia/protocol/openid-connect/token"


def test_the_host_reaches_keycloak_at_its_published_port(monkeypatch):
    monkeypatch.setattr(kcs.common, "in_container", lambda: False)
    root = {"KEYCLOAK_EXT_PORT": "18110", "OIDC_TOKEN_URL": _INTERNAL_TOKEN_URL}
    # The internal name does not resolve on the host, so it is never used there.
    assert kcs._admin_base_url(root) == "https://localhost:18110"


@pytest.mark.parametrize(
    ("host_ip", "expected"),
    [
        ("", "https://localhost:8110"),
        ("0.0.0.0", "https://localhost:8110"),
        ("::", "https://localhost:8110"),
        ("10.42.0.1", "https://10.42.0.1:8110"),
        ("[::]", "https://localhost:8110"),
        ("[fd00::1]", "https://[fd00::1]:8110"),
        ("fd00::1", "https://[fd00::1]:8110"),
    ],
)
def test_the_host_dials_the_address_the_port_is_published_on(monkeypatch, host_ip, expected):
    # --host-ip binds the published port to one address; localhost is refused there.
    monkeypatch.setattr(kcs.common, "in_container", lambda: False)
    assert kcs._admin_base_url({"HOST_IP": host_ip}) == expected


def test_a_container_ignores_the_host_ip(monkeypatch):
    monkeypatch.setattr(kcs.common, "in_container", lambda: True)
    root = {"HOST_IP": "10.42.0.1", "OIDC_TOKEN_URL": _INTERNAL_TOKEN_URL}
    assert kcs._admin_base_url(root) == "https://keycloak:8443"


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("https://localhost:8110", None),
        ("https://keycloak:8443", None),
        ("https://10.42.0.1:8110", "localhost"),
        ("https://[fd00::1]:8110", "localhost"),
    ],
)
def test_an_address_is_verified_as_localhost(base_url, expected):
    # The local CA certificate names localhost, never the --host-ip address.
    assert kcs._tls_server_name(base_url) == expected


def test_the_server_name_context_overrides_the_url_host(tmp_path, monkeypatch):
    ctx = kcs._ssl_context(tmp_path, "localhost")
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname

    seen = {}

    def _record(self, sock, *args, server_hostname=None, **kwargs):
        seen["name"] = server_hostname

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", _record)
    ctx.wrap_socket(object(), server_hostname="10.42.0.1")
    assert seen["name"] == "localhost"


def test_without_a_server_name_the_default_context_is_kept(tmp_path):
    assert not isinstance(kcs._ssl_context(tmp_path), kcs._ServerNameContext)


def test_the_published_port_defaults_to_the_shipped_one(monkeypatch):
    monkeypatch.setattr(kcs.common, "in_container", lambda: False)
    assert kcs._admin_base_url({}) == "https://localhost:8110"


def test_a_container_reaches_keycloak_at_the_address_the_stack_uses(monkeypatch):
    monkeypatch.setattr(kcs.common, "in_container", lambda: True)
    root = {"KEYCLOAK_EXT_PORT": "18110", "OIDC_TOKEN_URL": _INTERNAL_TOKEN_URL}
    assert kcs._admin_base_url(root) == "https://keycloak:8443"


@pytest.mark.parametrize(
    "token_url", ["", "   ", "keycloak:8443/realms", "ftp://keycloak/x", "not a url"]
)
def test_a_container_without_a_usable_internal_address_keeps_the_published_port(
    monkeypatch, token_url
):
    monkeypatch.setattr(kcs.common, "in_container", lambda: True)
    root = {"KEYCLOAK_EXT_PORT": "18110", "OIDC_TOKEN_URL": token_url}
    assert kcs._admin_base_url(root) == "https://localhost:18110"


def test_sync_talks_to_the_internal_address_in_a_container(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _realm_def())
    fake = FakeKeycloak()
    _patch_common(monkeypatch, fake)
    seen: dict[str, str] = {}

    def _wait(base_url, ctx, timeout=90):
        seen["wait"] = base_url

    def _token(base_url, ctx, password):
        seen["token"] = base_url
        return "fake-token"

    monkeypatch.setattr(kcs, "_wait_for_keycloak", _wait)
    monkeypatch.setattr(kcs, "_get_admin_token", _token)
    monkeypatch.setattr(kcs.common, "in_container", lambda: True)
    tree = _tree()
    tree[""]["OIDC_TOKEN_URL"] = _INTERNAL_TOKEN_URL

    assert kcs.sync_roles(tree, config_dir=tmp_path) is True
    assert seen == {"wait": "https://keycloak:8443", "token": "https://keycloak:8443"}


def test_sync_still_uses_the_published_port_on_the_host(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _realm_def())
    _patch_common(monkeypatch, FakeKeycloak())
    seen: dict[str, str] = {}

    def _wait(base_url, ctx, timeout=90):
        seen["wait"] = base_url

    monkeypatch.setattr(kcs, "_wait_for_keycloak", _wait)
    monkeypatch.setattr(kcs.common, "in_container", lambda: False)
    tree = _tree()
    tree[""]["OIDC_TOKEN_URL"] = _INTERNAL_TOKEN_URL

    assert kcs.sync_roles(tree, config_dir=tmp_path) is True
    assert seen == {"wait": "https://localhost:8110"}


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


def _themed_realm_def() -> dict:
    realm_def = _realm_def()
    realm_def["clients"][0]["attributes"] = {"login_theme": "papaia"}
    return realm_def


def _existing_oauth2_proxy(attributes: dict | None = None) -> dict:
    client = {"clientId": "oauth2-proxy", "mappers": {}}
    if attributes is not None:
        client["attributes"] = attributes
    return {"uuid-oauth2-proxy": client}


def test_an_existing_client_gets_the_login_theme_and_keeps_its_attributes(
    tmp_path, monkeypatch, capsys
):
    _write_realm_json(tmp_path, _themed_realm_def())
    fake = FakeKeycloak(
        roles={"user": _role("user")},
        clients=_existing_oauth2_proxy({"pkce.code.challenge.method": "S256"}),
    )
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    client = fake.clients["uuid-oauth2-proxy"]
    assert client["attributes"] == {
        "pkce.code.challenge.method": "S256",
        "login_theme": "papaia",
    }
    out = capsys.readouterr().out
    assert "login theme set: oauth2-proxy" in out
    assert "1 login theme(s) set" in out


def test_a_login_theme_chosen_by_hand_is_never_overwritten(tmp_path, monkeypatch):
    _write_realm_json(tmp_path, _themed_realm_def())
    fake = FakeKeycloak(
        roles={"user": _role("user")},
        clients=_existing_oauth2_proxy({"login_theme": "keycloak.v2"}),
    )
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    client = fake.clients["uuid-oauth2-proxy"]
    assert client["attributes"] == {"login_theme": "keycloak.v2"}
    assert "put_bodies" not in client


def test_the_login_theme_is_set_once(tmp_path, monkeypatch, capsys):
    _write_realm_json(tmp_path, _themed_realm_def())
    fake = FakeKeycloak(roles={"user": _role("user")}, clients=_existing_oauth2_proxy())
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True
    assert kcs.sync_roles(_tree(), config_dir=tmp_path) is True

    assert len(fake.clients["uuid-oauth2-proxy"]["put_bodies"]) == 1
    assert "0 login theme(s) set" in capsys.readouterr().out


# ── Add-on clients (addon_api 4) ─────────────────────────────────────────


def _addon(tmp_path, *, env, secrets=None, active=True, name="wiki"):
    """An add-on checkout with one client export, its bundle .env and a deployment entry."""
    addon_path = tmp_path / "checkout" / name
    (addon_path / "kc").mkdir(parents=True)
    (addon_path / "kc" / "wiki.json").write_text(
        json.dumps(
            {
                "id": "uuid-from-the-exporting-realm",
                "clientId": "wiki",
                "rootUrl": "https://wiki.example",
                "redirectUris": ["/login"],
                "protocolMappers": [{"name": "groups", "protocolMapper": "x", "config": {}}],
            }
        ),
        encoding="utf-8",
    )
    (addon_path / "papaia-app.yaml").write_text(
        yaml.safe_dump(
            {
                "name": name,
                "integration": {
                    "keycloak": {"clients": ["kc/wiki.json"], "client_secrets": secrets or {}}
                },
            }
        ),
        encoding="utf-8",
    )
    bundle = tmp_path / "config" / "addons" / name
    bundle.mkdir(parents=True)
    (bundle / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    (tmp_path / "config" / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": name, "path": str(addon_path), "active": active}]}),
        encoding="utf-8",
    )
    return tmp_path / "config"


_SECRETS = {"kc/wiki.json": {"secret_env": "KC_WIKI_SECRET", "root_url_env": "WIKI_SERVER"}}


def test_managed_clients_need_a_listed_path_and_a_secret_key():
    def managed(clients, secrets):
        return kcs.managed_clients(
            {"integration": {"keycloak": {"clients": clients, "client_secrets": secrets}}}
        )

    assert managed(["kc/wiki.json"], {}) == []
    assert managed([], {"kc/wiki.json": {"secret_env": "S"}}) == []
    assert managed(["kc/wiki.json"], {"kc/wiki.json": {"root_url_env": "U"}}) == []
    assert managed(["kc/wiki.json"], {"kc/wiki.json": {"secret_env": "S"}}) == [
        {"path": "kc/wiki.json", "secret_env": "S", "root_url_env": None}
    ]


def test_addon_clients_carry_the_secret_and_root_url_of_the_addon_env(tmp_path):
    config = _addon(
        tmp_path,
        secrets=_SECRETS,
        env={"KC_WIKI_SECRET": "s3cret", "WIKI_SERVER": "https://wiki.test:8020"},
    )
    (client,) = kcs.addon_clients(config, tmp_path)
    assert client["secret"] == "s3cret"
    assert client["rootUrl"] == "https://wiki.test:8020"
    assert client["clientAuthenticatorType"] == "client-secret"
    assert "id" not in client  # Keycloak assigns its own


@pytest.mark.parametrize("secret", ["", "GENERATE_SECRET", "REPLACE_WITH_SECRET", "CHANGE_ME"])
def test_a_placeholder_secret_is_generated_into_the_env(tmp_path, secret):
    config = _addon(tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": secret, "OTHER": "kept"})
    (client,) = kcs.addon_clients(config, tmp_path)
    env = (config / "addons" / "wiki" / ".env").read_text(encoding="utf-8")
    assert f"KC_WIKI_SECRET={client['secret']}\n" in env and len(client["secret"]) == 48
    assert "OTHER=kept" in env
    # The next run keeps it.
    (again,) = kcs.addon_clients(config, tmp_path)
    assert again["secret"] == client["secret"]


def test_a_client_whose_secret_key_is_missing_is_left_out(tmp_path, capsys):
    config = _addon(tmp_path, secrets=_SECRETS, env={"OTHER": "x"})
    assert kcs.addon_clients(config, tmp_path) == []
    assert "KC_WIKI_SECRET is not in its .env" in capsys.readouterr().err


def test_plain_entries_and_inactive_addons_stay_manual(tmp_path):
    config = _addon(tmp_path, env={"KC_WIKI_SECRET": "s"})
    assert kcs.addon_clients(config, tmp_path) == []
    config = _addon(tmp_path / "b", secrets=_SECRETS, env={"KC_WIKI_SECRET": "s"}, active=False)
    assert kcs.addon_clients(config, tmp_path / "b") == []


def test_start_creates_the_addon_client_and_aligns_its_secret_later(tmp_path, monkeypatch):
    config = _addon(tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": "first"})
    _write_realm_json(config, _realm_def())
    proxy = {"uuid-oauth2-proxy": {"clientId": "oauth2-proxy", "mappers": {}}}
    fake = FakeKeycloak(roles={}, clients=proxy)
    _patch_common(monkeypatch, fake)

    assert kcs.sync_roles(_tree(), config_dir=config, repo_root=tmp_path) is True
    created = fake.clients["uuid-wiki"]
    assert created["created_from"]["secret"] == "first"
    assert "groups" in created["mappers"]

    # The operator rotates the secret in the add-on .env: the next start aligns it.
    (config / "addons" / "wiki" / ".env").write_text("KC_WIKI_SECRET=second\n", encoding="utf-8")
    created["secret"] = "first"
    assert kcs.sync_roles(_tree(), config_dir=config, repo_root=tmp_path) is True
    assert created["secret"] == "second"
    assert [c["clientId"] for c in fake.clients.values()].count("wiki") == 1


def test_addon_start_syncs_only_its_own_clients(tmp_path, monkeypatch):
    config = _addon(tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": "s"})
    fake = FakeKeycloak(roles={}, clients={})
    _patch_common(monkeypatch, fake)

    assert kcs.sync_addon_clients(_tree(), config, tmp_path, {"other"}) is True
    assert fake.clients == {}
    assert kcs.sync_addon_clients(_tree(), config, tmp_path, {"wiki"}) is True
    assert {c["clientId"] for c in fake.clients.values()} == {"wiki"}


def test_addon_clients_are_left_alone_with_an_external_provider(tmp_path, monkeypatch):
    config = _addon(tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": "s"})
    fake = FakeKeycloak(roles={}, clients={})
    _patch_common(monkeypatch, fake)
    tree = _tree()
    tree[""]["AUTH_PROVIDER"] = "external_oidc"
    assert kcs.sync_addon_clients(tree, config, tmp_path, None) is True
    assert fake.clients == {}


def test_addon_clients_verify_a_host_ip_connection_like_the_role_sync(tmp_path, monkeypatch):
    # The local CA certificate names localhost, not the --host-ip address: both syncs have to
    # dial the address and verify the name, or `addon start` fails where the role sync works.
    config = _addon(tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": "s"})
    _write_realm_json(config, _realm_def())
    fake = FakeKeycloak(roles={}, clients={})
    _patch_common(monkeypatch, fake)
    monkeypatch.setattr(kcs.common, "in_container", lambda: False)
    seen: list[tuple[str, str | None]] = []
    real = kcs._ssl_context

    def _record(config_dir, server_name=None):
        seen.append(("ctx", server_name))
        return real(config_dir, server_name)

    def _wait(base_url, ctx, timeout=90):
        seen.append(("url", base_url))

    monkeypatch.setattr(kcs, "_ssl_context", _record)
    monkeypatch.setattr(kcs, "_wait_for_keycloak", _wait)
    tree = _tree()
    tree[""]["HOST_IP"] = "10.42.0.1"

    assert kcs.sync_addon_clients(tree, config, tmp_path, {"wiki"}) is True
    addon_start = list(seen)
    seen.clear()
    assert kcs.sync_roles(tree, config_dir=config, repo_root=tmp_path) is True
    assert addon_start == seen == [("ctx", "localhost"), ("url", "https://10.42.0.1:8110")]


def test_addon_clients_wait_only_briefly_for_keycloak(tmp_path, monkeypatch, capsys):
    config = _addon(tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": "s"})
    _patch_common(monkeypatch, FakeKeycloak(roles={}, clients={}))
    waited = []

    def _down(base_url, ctx, timeout=90):
        waited.append(timeout)
        raise TimeoutError("Keycloak did not become ready")

    monkeypatch.setattr(kcs, "_wait_for_keycloak", _down)
    assert kcs.sync_addon_clients(_tree(), config, tmp_path, {"wiki"}) is False
    assert waited == [kcs.ADDON_CLIENTS_WAIT_SECONDS]
    assert "Keycloak clients skipped" in capsys.readouterr().err


def test_fill_client_secrets_replaces_only_placeholders(tmp_path, capsys):
    config = _addon(
        tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": "REPLACE_WITH_X", "OTHER": "kept"}
    )
    env_path = config / "addons" / "wiki" / ".env"
    manifest = yaml.safe_load((tmp_path / "checkout" / "wiki" / "papaia-app.yaml").read_text())

    assert kcs.fill_client_secrets(manifest, env_path, "wiki") == ["KC_WIKI_SECRET"]
    first = _env_of(env_path)
    assert len(first["KC_WIKI_SECRET"]) == 48 and first["OTHER"] == "kept"
    assert "KC_WIKI_SECRET of add-on wiki generated" in capsys.readouterr().out
    # A value that is set is never replaced.
    assert kcs.fill_client_secrets(manifest, env_path, "wiki") == []
    assert _env_of(env_path) == first


def test_a_secret_the_role_sync_generates_asks_for_an_addon_start(tmp_path, capsys):
    # The role sync runs after the add-on's .env reached its checkout; the add-on has to be
    # started again to pick up the new value.
    config = _addon(tmp_path, secrets=_SECRETS, env={"KC_WIKI_SECRET": "GENERATE_SECRET"})
    kcs.addon_clients(config, tmp_path)
    assert "run 'papaia-ctl addon start wiki' so the add-on uses it" in capsys.readouterr().out


def _env_of(path):
    return kcs.common.parse_env_file(path)
