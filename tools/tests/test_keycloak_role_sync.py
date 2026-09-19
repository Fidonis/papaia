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

    def __init__(self, *, roles=None, clients=None, users=None):
        # role name -> {"id", "name", "description", "composite", "composites": set()}
        self.roles: dict[str, dict] = roles or {}
        # client uuid -> {"clientId", "mappers": {name: mapper}}
        self.clients: dict[str, dict] = clients or {}
        # user id -> {"username", "roles": set()}
        self.users: dict[str, dict] = users or {}

    def _role_rep(self, name: str) -> dict:
        r = self.roles[name]
        return {
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "composite": r["composite"],
        }

    def __call__(self, base_url, ctx, token, method, path, body=None):
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
            name = m.group(1)
            return [self._role_rep(c) for c in self.roles[name].get("composites", set())]
        if m and method == "POST":
            name = m.group(1)
            for rep in body:
                self.roles[name].setdefault("composites", set()).add(rep["name"])
            return None

        m = re.fullmatch(r"/roles/([^/]+)/users", path)
        if m and method == "GET":
            name = m.group(1)
            return [
                {"id": uid, "username": u["username"]}
                for uid, u in self.users.items()
                if name in u["roles"]
            ]

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
