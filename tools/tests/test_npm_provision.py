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
    """provision_npm_hosts returns immediately without any network calls
    when REVERSE_PROXY_PROVIDER is not 'internal_nginx'."""
    for provider in ("external_proxy", "no_proxy", ""):
        tree = {"": {"REVERSE_PROXY_PROVIDER": provider}}
        # If it tries to make HTTP calls it would raise ConnectionRefusedError;
        # completing silently proves it skipped them.
        npm_provision.provision_npm_hosts(tree)


def test_provision_raises_when_password_missing():
    tree = {
        "": {
            "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "NPM_ADMIN_EMAIL": "admin@papaia.local",
            "NPM_ADMIN_PASSWORD": "",
            "COMPOSE_PROFILES": "keycloak,nginx,librechat,litellm",
        }
    }
    with pytest.raises(RuntimeError, match="NPM_ADMIN_PASSWORD"):
        npm_provision.provision_npm_hosts(tree)


def test_provision_raises_when_password_is_placeholder():
    tree = {
        "": {
            "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "NPM_ADMIN_EMAIL": "admin@papaia.local",
            "NPM_ADMIN_PASSWORD": "GENERATE_NPM_ADMIN_PASSWORD",
            "COMPOSE_PROFILES": "keycloak,nginx,librechat,litellm",
        }
    }
    with pytest.raises(RuntimeError, match="NPM_ADMIN_PASSWORD"):
        npm_provision.provision_npm_hosts(tree)
