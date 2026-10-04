"""NPM proxy hosts of the rag profile: which hosts are created, and the path filter
that keeps the ingester's API planes off the public hostname."""

from __future__ import annotations

import json
import re

from lib import npm_provision


def _tree(profiles: str) -> dict[str, dict[str, str]]:
    return {
        "": {
            "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "COMPOSE_PROFILES": profiles,
            "QDRANT_PUBLIC_URL": "https://qdrant.example.com",
            "QDRANT_INGEST_PUBLIC_URL": "https://ingest.example.com",
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

    def record(base_url, token, domain, host, port, scheme, ssl_verify, ws, extra_config=""):
        created.append(
            {
                "domain": domain,
                "forward": f"{scheme}://{host}:{port}",
                "extra_config": extra_config,
            }
        )

    monkeypatch.setattr(npm_provision, "_create_proxy_host", record)
    assert npm_provision.provision_npm_hosts(tree) is True
    return created


def test_rag_hosts_are_provisioned_while_the_profile_is_active(monkeypatch):
    created = _provision(monkeypatch, _tree("keycloak,nginx,rag"))

    by_domain = {c["domain"]: c for c in created}
    assert by_domain["qdrant.example.com"]["forward"] == "http://qdrant:6333"
    assert by_domain["ingest.example.com"]["forward"] == "http://qdrant-ingest:8300"


def test_rag_hosts_are_not_provisioned_without_the_profile(monkeypatch):
    assert _provision(monkeypatch, _tree("keycloak,nginx")) == []


def test_rag_hosts_on_a_port_or_a_local_name_are_not_provisioned(monkeypatch):
    tree = _tree("rag")
    tree[""]["QDRANT_PUBLIC_URL"] = "https://papaia.example.com:6333"
    tree[""]["QDRANT_INGEST_PUBLIC_URL"] = "http://localhost:8300"

    assert _provision(monkeypatch, tree) == []


def test_an_existing_rag_host_is_left_alone(monkeypatch):
    created = _provision(monkeypatch, _tree("rag"), existing={"qdrant.example.com"})

    assert [c["domain"] for c in created] == ["ingest.example.com"]


def test_only_the_ingest_host_carries_the_path_filter(monkeypatch):
    by_domain = {c["domain"]: c for c in _provision(monkeypatch, _tree("rag"))}

    assert "return 404" in by_domain["ingest.example.com"]["extra_config"]
    assert by_domain["qdrant.example.com"]["extra_config"] == ""


def test_the_extra_config_is_appended_to_the_advanced_config(monkeypatch):
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
    create(base, "t", "a.example.com", "svc", 80, "http", True, False, "# x\n")
    create(base, "t", "b.example.com", "svc", 443, "https", False, False, "# x\n")
    create(base, "t", "c.example.com", "svc", 80, "http", True, False)

    assert sent[0]["advanced_config"] == "# x\n"
    assert sent[1]["advanced_config"] == "proxy_ssl_verify off;\n# x\n"
    assert sent[2]["advanced_config"] == ""


def test_the_ingest_filter_lets_only_the_interface_and_health_through():
    """The filter is nginx regex syntax, which Python's `re` reads the same way for
    this pattern; the allow-list it encodes is what is pinned here. The rule itself
    was also run through nginx."""
    config = npm_provision._PROXY_HOST_EXTRA_CONFIG["QDRANT_INGEST_PUBLIC_URL"]
    match = re.fullmatch(r"location ~ (\S+) \{ return 404; \}\n", config)
    assert match, config
    blocked = re.compile(match.group(1))

    allowed = ["/ui", "/ui/", "/ui/auth/login", "/ui/auth/callback", "/ui/static/a.css", "/health"]
    refused = ["/", "/v1/jobs", "/mcp", "/metrics", "/docs", "/openapi.json", "/uix", "/healthz"]
    for path in allowed:
        assert not blocked.match(path), path
    for path in refused:
        assert blocked.match(path), path
