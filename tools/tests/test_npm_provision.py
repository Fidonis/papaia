from __future__ import annotations

import pytest

from lib import npm_provision


@pytest.mark.parametrize(
    "url,expected",
    [
        # Clean subdomain URLs — should create an NPM entry
        ("https://auth.papaia.example.com", True),
        ("https://chat.papaia.example.com", True),
        ("https://llmproxy.papaia.example.com", True),
        ("http://llmproxy.papaia.example.com", True),
        # Port-based URLs — direct access, no NPM entry
        ("https://papaia.example.com:8200", False),
        ("http://papaia.example.com:8100", False),
        ("https://papaia.example.com:443", False),
        # Local / internal addresses — no NPM entry
        ("http://host.docker.internal:8000", False),
        ("http://localhost:3080", False),
        ("http://127.0.0.1:4000", False),
        # Edge cases
        ("", False),
        ("not-a-url", False),
    ],
)
def test_is_subdomain_url(url, expected):
    assert npm_provision._is_subdomain_url(url) is expected


def test_provision_noop_when_not_internal_nginx():
    """provision_npm_hosts returns True immediately without any network calls
    when REVERSE_PROXY_PROVIDER is not 'internal_nginx'."""
    for provider in ("external_proxy", "no_proxy", ""):
        tree = {"": {"REVERSE_PROXY_PROVIDER": provider}}
        # If it tries to make HTTP calls it would raise ConnectionRefusedError;
        # returning True proves it skipped them.
        assert npm_provision.provision_npm_hosts(tree) is True


def _tree(npm_password: str) -> dict[str, dict[str, str]]:
    """Minimal env tree with the bundled proxy selected. The NPM credentials
    live in the nginx module's own .env, not the root one."""
    return {
        "": {
            "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "COMPOSE_PROFILES": "keycloak,nginx,librechat,litellm",
        },
        "infra/nginx": {
            "NPM_ADMIN_EMAIL": "admin@papaia.local",
            "NPM_ADMIN_PASSWORD": npm_password,
            "NPM_API_LOCAL_PORT": "8181",
        },
    }


def test_provision_raises_when_password_missing():
    with pytest.raises(RuntimeError, match="NPM_ADMIN_PASSWORD"):
        npm_provision.provision_npm_hosts(_tree(""))


def test_provision_raises_when_password_is_placeholder():
    with pytest.raises(RuntimeError, match="NPM_ADMIN_PASSWORD"):
        npm_provision.provision_npm_hosts(_tree("GENERATE_NPM_ADMIN_PASSWORD"))


def test_provision_raises_when_nginx_node_absent():
    """A tree without the nginx node at all must fail loudly rather than
    silently authenticate with an empty password."""
    tree = {"": {"REVERSE_PROXY_PROVIDER": "internal_nginx", "COMPOSE_PROFILES": "nginx"}}
    with pytest.raises(RuntimeError, match="NPM_ADMIN_PASSWORD"):
        npm_provision.provision_npm_hosts(tree)


def test_provision_returns_false_on_timeout(monkeypatch, capsys):
    """provision_npm_hosts returns False and prints a stderr message when NPM
    does not become ready within the timeout — no exception is raised."""

    def _fake_wait(base_url: str, timeout: int = 60) -> None:
        raise TimeoutError(f"NPM API at {base_url} did not become ready within {timeout}s")

    monkeypatch.setattr(npm_provision, "_wait_for_npm", _fake_wait)
    result = npm_provision.provision_npm_hosts(_tree("correct-password"))
    assert result is False
    captured = capsys.readouterr()
    assert "NPM" in captured.err


def test_the_identity_provider_host_refuses_the_admin_api():
    """Keycloak's admin API is never routed through the edge (CORE-007b); the admin steps
    reach it on the stack network."""
    body = npm_provision.core_host_body("auth.example.org", "keycloak", 8443, "https", False, True)
    advanced = body["advanced_config"]
    assert npm_provision.IDP_ADMIN_BLOCK in advanced
    assert "return 403;" in advanced and "^/admin(/|$)" in advanced
    assert "proxy_ssl_verify off;" in advanced


@pytest.mark.parametrize("service", ["librechat", "litellm", "papaia-manager"])
def test_other_core_hosts_carry_no_admin_block(service):
    body = npm_provision.core_host_body("x.example.org", service, 8000, "http", True, True)
    assert npm_provision.IDP_ADMIN_BLOCK not in (body.get("advanced_config") or "")


def _idp_tree() -> dict[str, dict[str, str]]:
    tree = _tree("correct-password")
    tree[""].update({"COMPOSE_PROFILES": "keycloak,nginx", "AUTH_HOST": "https://auth.example.org"})
    return tree


def _provision_with_hosts(monkeypatch, hosts: list[dict]) -> list[tuple[str, object, dict]]:
    """Run provision_npm_hosts against a fake NPM API holding `hosts`; the writes made."""
    writes: list[tuple[str, object, dict]] = []
    monkeypatch.setattr(npm_provision, "_wait_for_npm", lambda base_url, timeout=60: None)
    monkeypatch.setattr(npm_provision, "_get_token", lambda base_url, email, password: "t")
    monkeypatch.setattr(npm_provision, "_list_proxy_hosts", lambda base_url, token: hosts)
    monkeypatch.setattr(
        npm_provision, "_put_proxy_host",
        lambda base_url, token, host_id, body: writes.append(("PUT", host_id, body)),
    )
    monkeypatch.setattr(
        npm_provision, "_post_proxy_host",
        lambda base_url, token, body: writes.append(("POST", None, body)),
    )
    assert npm_provision.provision_npm_hosts(_idp_tree()) is True
    return writes


def _operator_idp_host(**fields) -> dict:
    """The identity provider's host as an operator left it in the NPM UI: a certificate,
    forced SSL, HSTS and an extra location of their own."""
    wanted = npm_provision.core_host_body(
        "auth.example.org", "keycloak", 8443, "https", False, False
    )
    return {
        **wanted,
        "id": 7,
        "certificate_id": 3,
        "ssl_forced": True,
        "hsts_enabled": True,
        "http2_support": True,
        "locations": [{"path": "/health", "forward_host": "keycloak", "forward_port": 9000}],
        **fields,
    }


def test_the_identity_provider_host_keeps_the_operators_certificate_and_settings(monkeypatch):
    assert _provision_with_hosts(monkeypatch, [_operator_idp_host()]) == []


def test_a_drifted_identity_provider_host_gets_back_only_the_fields_setup_owns(monkeypatch):
    host = _operator_idp_host(advanced_config="", forward_host="elsewhere")
    writes = _provision_with_hosts(monkeypatch, [host])
    assert len(writes) == 1
    method, host_id, body = writes[0]
    assert (method, host_id) == ("PUT", 7)
    assert npm_provision.IDP_ADMIN_BLOCK in body["advanced_config"]
    assert body["forward_host"] == "keycloak" and body["forward_port"] == 8443
    # Nothing the operator owns is sent back, so NPM keeps it.
    for key in ("certificate_id", "ssl_forced", "hsts_enabled", "http2_support", "locations"):
        assert key not in body
