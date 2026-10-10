"""NPM proxy hosts of the rag profile: which hosts are created. The ingester has no web
interface, so it gets no public host; only Qdrant does."""

from __future__ import annotations

import json

from lib import npm_provision


def _tree(profiles: str) -> dict[str, dict[str, str]]:
    return {
        "": {
            "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "COMPOSE_PROFILES": profiles,
            "QDRANT_PUBLIC_URL": "https://qdrant.example.com",
        },
        "infra/nginx": {
            "NPM_ADMIN_EMAIL": "admin@papaia.local",
            "NPM_ADMIN_PASSWORD": "secret",
            "NPM_API_LOCAL_PORT": "8181",
        },
    }


def _provision(monkeypatch, tree, existing=()):
    """Run provision_npm_hosts against a recording stand-in for the NPM API."""
    created: list[dict] = []
    monkeypatch.setattr(npm_provision, "_wait_for_npm", lambda base_url, timeout=60: None)
    monkeypatch.setattr(npm_provision, "_get_token", lambda base_url, email, password: "token")
    monkeypatch.setattr(npm_provision, "_existing_domains", lambda base_url, token: set(existing))

    def record(base_url, token, domain, host, port, scheme, ssl_verify, ws):
        created.append({"domain": domain, "forward": f"{scheme}://{host}:{port}"})

    monkeypatch.setattr(npm_provision, "_create_proxy_host", record)
    assert npm_provision.provision_npm_hosts(tree) is True
    return created


def test_the_qdrant_host_is_provisioned_while_the_profile_is_active(monkeypatch):
    created = _provision(monkeypatch, _tree("keycloak,nginx,rag"))

    assert created == [{"domain": "qdrant.example.com", "forward": "http://qdrant:6333"}]


def test_rag_hosts_are_not_provisioned_without_the_profile(monkeypatch):
    assert _provision(monkeypatch, _tree("keycloak,nginx")) == []


def test_a_qdrant_host_on_a_port_or_a_local_name_is_not_provisioned(monkeypatch):
    tree = _tree("rag")
    tree[""]["QDRANT_PUBLIC_URL"] = "https://papaia.example.com:6333"

    assert _provision(monkeypatch, tree) == []


def test_an_existing_qdrant_host_is_left_alone(monkeypatch):
    assert _provision(monkeypatch, _tree("rag"), existing={"qdrant.example.com"}) == []


def test_an_ingest_url_left_in_an_earlier_env_gets_no_host(monkeypatch):
    """An installation set up before the web interface went away still stores the URL.
    Nothing reads it any more, so no proxy host is created for it."""
    tree = _tree("rag")
    tree[""]["QDRANT_INGEST_PUBLIC_URL"] = "https://ingest.example.com"

    created = _provision(monkeypatch, tree)

    assert [c["domain"] for c in created] == ["qdrant.example.com"]


def test_the_advanced_config_turns_off_upstream_verification_only_when_asked(monkeypatch):
    sent: list[dict] = []

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=0):
        sent.append(json.loads(request.data))
        return _Response()

    monkeypatch.setattr(npm_provision.urllib.request, "urlopen", fake_urlopen)
    base = "http://localhost:8181"

    create = npm_provision._create_proxy_host
    create(base, "t", "a.example.com", "svc", 80, "http", True, False)
    create(base, "t", "b.example.com", "svc", 443, "https", False, False)

    assert sent[0]["advanced_config"] == ""
    assert sent[1]["advanced_config"] == "proxy_ssl_verify off;\n"
