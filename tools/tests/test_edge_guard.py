"""The edge refuses platform writes from Studio app hosts (security §4.1 (3), E-20).

Without a second domain the Studio apps live on `apps.<domain>` and its subdomains, on
the platform's own site, so `SameSite` no longer keeps a browser from sending the
platform's cookies along with a request an app makes. The bundled proxy therefore
refuses every state-changing request whose `Origin` is an app host, on every proxy host,
and writes one `papaia.audit/1` row for it.

The nginx side is checked with real containers in test_edge_guard_docker.py; here the
generated configuration, its merge into the proxy manager's custom files, the
provisioning step and the `doctor` check are tested without Docker.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lib import edge_guard, ingress, npm_provision, paperless_gate, startgate

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads(
    (REPO / "src" / "infra" / "audit" / "papaia_audit" / "audit.v1.schema.json").read_text(
        encoding="utf-8"
    )
)


def _root(**values: str) -> dict[str, str]:
    return {"REVERSE_PROXY_PROVIDER": "internal_nginx", **values}


# ── which hosts are app hosts ────────────────────────────────────────────────


def test_without_a_second_domain_the_app_hosts_are_below_apps_of_the_domain():
    root = _root(PAPAIA_HOST="https://example.com")

    assert edge_guard.app_host_bases(root) == ["apps.example.com"]


def test_a_second_domain_is_an_app_host_and_apps_of_the_domain_stays_one():
    root = _root(PAPAIA_HOST="https://example.com", INGRESS_APP_DOMAIN="example-apps.org")

    assert edge_guard.app_host_bases(root) == ["apps.example.com", "example-apps.org"]


def test_a_local_installation_has_both_local_app_domains():
    root = _root(PAPAIA_HOST="https://host.docker.internal", COMPOSE_PROJECT_NAME="papaia-itest")

    assert edge_guard.app_host_bases(root) == [
        "apps.itest.papaia.localhost",
        "itest.papaia-apps.localhost",
    ]


def test_without_a_proxy_there_are_no_app_hosts():
    assert edge_guard.app_host_bases({"REVERSE_PROXY_PROVIDER": "no_proxy"}) == []


def test_an_unusable_app_domain_is_refused():
    with pytest.raises(ingress.IngressError):
        edge_guard.app_host_bases(
            _root(PAPAIA_HOST="https://example.com", INGRESS_APP_DOMAIN="apps.example.com")
        )


# ── the Origin pattern ───────────────────────────────────────────────────────


def _pattern(bases: list[str]) -> re.Pattern[str]:
    regex = edge_guard.origin_regex(bases)
    assert regex is not None
    # nginx's `~*`: a case-insensitive PCRE match; the pattern uses nothing PCRE and
    # Python read differently.
    return re.compile(regex, re.IGNORECASE)


@pytest.mark.parametrize(
    "origin",
    [
        "https://apps.example.com",
        "https://apps.example.com:8443",
        "http://apps.example.com",
        "https://crm.apps.example.com",
        "https://a.b.apps.example.com:443",
        "HTTPS://APPS.EXAMPLE.COM",
        "https://example-apps.org",
        "https://report.example-apps.org",
    ],
)
def test_an_app_host_origin_matches(origin):
    assert _pattern(["apps.example.com", "example-apps.org"]).search(origin)


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "null",
        "https://example.com",
        "https://chat.example.com",
        "https://studio.example.com",
        "https://auth.example.com:8443",
        "https://myapps.example.com",
        "https://apps.example.com.evil.org",
        "https://apps.example.com@evil.org",
        "https://apps-example.com",
        "https://appsXexample.com",
        "https://example-apps.org.evil.org",
        "https://apps.example.com/",
        "https://apps.example.com:844301",
        "https://apps.example.com\nX: y",
    ],
)
def test_a_platform_or_foreign_origin_does_not_match(origin):
    assert not _pattern(["apps.example.com", "example-apps.org"]).search(origin)


def test_no_app_hosts_means_no_pattern_and_a_guard_that_never_refuses():
    assert edge_guard.origin_regex([]) is None
    block = edge_guard.http_block([])
    assert "map $http_origin $papaia_app_origin" in block
    origins = re.search(r"map \$http_origin \$papaia_app_origin \{\n(.*?)\n\}\n", block, re.S)
    assert origins.group(1).strip() == "default 0;"


def test_an_app_host_base_that_is_no_domain_is_refused():
    with pytest.raises(ValueError):
        edge_guard.origin_regex(["apps.example.com|.*"])


# ── the configuration the proxy manager includes ─────────────────────────────


def test_only_state_changing_methods_with_an_app_origin_are_refused():
    block = edge_guard.http_block(["apps.example.com"])

    methods = re.search(
        r"map \$request_method \$papaia_unsafe_method \{\n(.*?)\n\}\n", block, re.S
    )
    assert methods is not None
    lines = {line.strip() for line in methods.group(1).splitlines() if line.strip()}
    assert lines == {"GET 0;", "HEAD 0;", "OPTIONS 0;", "default 1;"}
    write = re.search(
        r'map "\$papaia_unsafe_method:\$papaia_app_origin" \$papaia_app_write \{\n(.*?)\n\}\n',
        block,
        re.S,
    )
    assert write is not None
    assert '"1:1" 1;' in write.group(1)
    assert 'default "";' in write.group(1)


def test_every_proxy_host_refuses_with_403_and_writes_the_audit_line():
    block = edge_guard.server_block()

    assert f"access_log {edge_guard.AUDIT_LOG} papaia_audit if=$papaia_app_write;" in block
    assert "if ($papaia_app_write) {\n    return 403;\n}" in block
    assert "add_header X-Papaia-Error $papaia_app_write_error always;" in block
    assert "add_header X-Papaia-Correlation-Id $papaia_app_write_correlation always;" in block


def _audit_line(block: str, values: dict[str, str]) -> dict:
    """The log line nginx writes, with the variables of the format filled in."""
    match = re.search(r"log_format papaia_audit escape=json '(.*?)';", block, re.S)
    assert match is not None
    template = match.group(1)

    def fill(m: re.Match[str]) -> str:
        return values[m.group(1) or m.group(2)]

    return json.loads(re.sub(r"\$\{([a-z_]+)\}|\$([a-z_]+)", fill, template))


def _submission_errors(row: dict) -> list[str]:
    # The delivering writer numbers the rows (source_seq), as for papaia-egress.
    validator = Draft202012Validator({"$defs": SCHEMA["$defs"], "$ref": "#/$defs/submission"})
    return [e.message for e in validator.iter_errors({**row, "source_seq": 1})]


def test_the_audit_line_is_a_papaia_audit_row_without_person_origin_or_content():
    block = edge_guard.http_block(["apps.example.com"])

    row = _audit_line(
        block,
        {
            "papaia_audit_second": "2026-11-23T10:15:00",
            "papaia_audit_milli": "042",
            "request_id": "0123456789abcdef0123456789abcdef",
            "papaia_audit_host": "manager.example.com",
        },
    )

    assert row == {
        "format": "papaia.audit/1",
        "time": "2026-11-23T10:15:00.042Z",
        "correlation_id": "0123456789abcdef0123456789abcdef",
        "writer": "papaia-edge",
        "role": "server",
        "sub": None,
        "identity_kind": None,
        "azp": None,
        "catalog_id": None,
        "operation": "edge.write",
        "effect": "write",
        "object_ref": {"type": "host", "id": "manager.example.com"},
        "result": "denied",
        "error_code": "app_origin_refused",
        "event": "protected_host_denied",
    }
    assert _submission_errors(row) == []


def test_the_audit_line_takes_no_value_from_the_request_but_the_checked_host():
    block = edge_guard.http_block(["apps.example.com"])
    template = re.search(r"log_format papaia_audit escape=json '(.*?)';", block, re.S).group(1)

    assert set(re.findall(r"\$\{?([a-z_]+)", template)) == {
        "papaia_audit_second",
        "papaia_audit_milli",
        "request_id",
        "papaia_audit_host",
    }
    host = re.search(r"map \$host \$papaia_audit_host \{\n(.*?)\n\}\n", block, re.S).group(1)
    assert '"~^[a-z0-9][a-z0-9.-]{0,252}$" $host;' in host
    assert "default unknown;" in host


def test_the_audit_time_is_utc_with_milliseconds():
    block = edge_guard.http_block([])

    second = re.search(r"map \$time_iso8601 \$papaia_audit_second \{\n(.*?)\n\}\n", block, re.S)
    milli = re.search(r"map \$msec \$papaia_audit_milli \{\n(.*?)\n\}\n", block, re.S)
    assert second is not None and milli is not None
    # Only a UTC time is taken (the proxy's container runs in UTC). PCRE's
    # `(?<name>` is Python's `(?P<name>`.
    regex = re.search(r'"~(.*?)" \$papaia_t_second;', second.group(1)).group(1)
    regex = regex.replace("(?<", "(?P<")
    assert re.match(regex, "2026-11-23T10:15:00+00:00").group("papaia_t_second") == (
        "2026-11-23T10:15:00"
    )
    assert not re.match(regex, "2026-11-23T11:15:00+01:00")
    regex = re.search(r'"~(.*?)" \$papaia_t_milli;', milli.group(1)).group(1)
    regex = regex.replace("(?<", "(?P<")
    assert re.search(regex, "1763892900.042").group("papaia_t_milli") == "042"


def test_refusals_count_the_lines_and_those_without_a_utc_time(config_dir):
    assert edge_guard.refusals(config_dir) is None
    log = edge_guard.host_path(config_dir, edge_guard.AUDIT_LOG)
    log.parent.mkdir(parents=True)
    log.write_text(
        '{"time":"2026-11-23T10:15:00.042Z"}\n{"time":".042Z"}\n\nnot json\n',
        encoding="utf-8",
    )

    assert edge_guard.refusals(config_dir) == 3
    assert edge_guard.lines_without_time(config_dir) == 2


# ── merging into the proxy manager's custom files ────────────────────────────


def test_the_http_file_keeps_what_the_operator_wrote_and_is_idempotent():
    block = edge_guard.http_block(["apps.example.com"])
    operator = "# operator\nmap $http_x $y { default 0; }\n"

    merged = edge_guard.merge_http(operator, block)

    assert merged == block + operator
    assert edge_guard.merge_http(merged, block) == merged
    newer = edge_guard.http_block(["apps.example.com", "example-apps.org"])
    assert edge_guard.merge_http(merged, newer) == newer + operator


def test_the_server_file_keeps_the_header_strip_first_and_the_operator_lines_last():
    strip = paperless_gate.strip_config()
    guard = edge_guard.server_block()
    operator = "add_header X-Operator yes;\n"

    # Whichever step runs first, both managed blocks end up on top, the strip first.
    guard_first = edge_guard.merge_server(operator, guard)
    assert guard_first == guard + operator
    both = paperless_gate.merge_strip(guard_first)
    assert both == strip + guard + operator
    assert edge_guard.merge_server(both, guard) == both
    assert paperless_gate.merge_strip(both) == both
    strip_first = edge_guard.merge_server(paperless_gate.merge_strip(operator), guard)
    assert strip_first == both


def test_the_server_file_keeps_the_start_gate_next_to_the_strip_and_one_guard():
    strip = paperless_gate.strip_config()
    gate = startgate.edge_block({"manager.example.com": "core"}, contact=None)
    guard = edge_guard.server_block()
    operator = "add_header X-Operator yes;\n"

    # npm-provision writes the strip with the start gate first, then the guard: the
    # guard goes after the start gate, and a second run changes neither file.
    gated = paperless_gate.merge_strip(operator, gate)
    assert gated == strip + gate + operator
    guarded = edge_guard.merge_server(gated, guard)
    assert guarded == strip + gate + guard + operator
    assert paperless_gate.merge_strip(guarded, gate) == guarded
    assert edge_guard.merge_server(guarded, guard) == guarded

    # A guard left below the start gate by an earlier order is moved, never repeated.
    earlier = strip + guard + gate + operator
    assert edge_guard.merge_server(paperless_gate.merge_strip(earlier, gate), guard) == guarded
    assert edge_guard.merge_server(strip + gate + operator + guard, guard) == guarded
    # Without the lifecycle profile the start gate goes and the guard stays.
    assert paperless_gate.merge_strip(guarded) == strip + guard + operator


# ── provisioning ─────────────────────────────────────────────────────────────


class _Proxy:
    """The two custom files in a stand-in for the proxy container."""

    def __init__(self, files: dict[str, str] | None = None, *, config_ok: bool = True):
        self.files = dict(files or {})
        self.config_ok = config_ok
        self.writes: list[str] = []

    def read(self, container: str, target: str) -> str | None:
        return self.files.get(target, "")

    def write(self, container: str, target: str, text: str) -> bool:
        self.files[target] = text
        self.writes.append(target)
        return True

    def test(self, container: str) -> bool:
        return self.config_ok


def _install(monkeypatch, proxy: _Proxy, container: str | None = "abc"):
    monkeypatch.setattr(edge_guard, "_proxy_container", lambda project: container)
    monkeypatch.setattr(edge_guard, "_read", proxy.read)
    monkeypatch.setattr(edge_guard, "_write", proxy.write)
    monkeypatch.setattr(edge_guard, "_config_test", proxy.test)


def test_install_writes_the_http_file_before_the_server_file(monkeypatch):
    proxy = _Proxy()
    _install(monkeypatch, proxy)

    assert edge_guard.install("papaia", ["apps.example.com"]) is True

    assert proxy.writes == [edge_guard.HTTP_TARGET, edge_guard.SERVER_TARGET]
    assert proxy.files[edge_guard.HTTP_TARGET] == edge_guard.http_block(["apps.example.com"])
    assert proxy.files[edge_guard.SERVER_TARGET] == edge_guard.server_block()
    assert edge_guard.install("papaia", ["apps.example.com"]) is False
    assert len(proxy.writes) == 2


def test_a_configuration_the_proxy_refuses_is_rolled_back(monkeypatch):
    before = {edge_guard.HTTP_TARGET: "# mine\n", edge_guard.SERVER_TARGET: "# also mine\n"}
    proxy = _Proxy(before, config_ok=False)
    _install(monkeypatch, proxy)

    assert edge_guard.install("papaia", ["apps.example.com"]) is None

    assert proxy.files == before


def test_install_without_a_running_proxy_reports_none(monkeypatch):
    proxy = _Proxy()
    _install(monkeypatch, proxy, container=None)

    assert edge_guard.install("papaia", ["apps.example.com"]) is None
    assert proxy.writes == []


def _nginx_tree(**root: str) -> dict[str, dict[str, str]]:
    return {
        "": {
            "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "COMPOSE_PROFILES": "keycloak,nginx",
            "COMPOSE_PROJECT_NAME": "papaia",
            "PAPAIA_HOST": "https://example.com",
            **root,
        },
        "infra/nginx": {
            "NPM_ADMIN_EMAIL": "admin@papaia.local",
            "NPM_ADMIN_PASSWORD": "not-a-real-password",
            "NPM_API_LOCAL_PORT": "8181",
        },
    }


def _fake_npm(monkeypatch, guard_result, reloads: list[str]):
    monkeypatch.setattr(npm_provision, "_wait_for_npm", lambda base_url, timeout=60: None)
    monkeypatch.setattr(npm_provision, "_get_token", lambda base_url, email, password: "t")
    monkeypatch.setattr(npm_provision, "_existing_domains", lambda base_url, token: set())
    monkeypatch.setattr(npm_provision, "_create_proxy_host", lambda *a, **k: None)
    monkeypatch.setattr(npm_provision, "_list_proxy_hosts", lambda base_url, token: [])
    monkeypatch.setattr(paperless_gate, "install_strip_file", lambda project, extra="": False)
    monkeypatch.setattr(
        paperless_gate, "reload_proxy", lambda project: reloads.append(project) or True
    )
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        edge_guard, "install", lambda project, bases: calls.append((project, bases)) or guard_result
    )
    return calls


def test_provisioning_installs_the_guard_for_the_app_hosts_and_reloads(config_dir, monkeypatch):
    reloads: list[str] = []
    calls = _fake_npm(monkeypatch, True, reloads)

    tree = _nginx_tree(INGRESS_APP_DOMAIN="example-apps.org")
    assert npm_provision.provision_npm_hosts(tree, config_dir) is True

    assert calls == [("papaia", ["apps.example.com", "example-apps.org"])]
    assert reloads == ["papaia"]


def test_an_unchanged_guard_does_not_reload(config_dir, monkeypatch):
    reloads: list[str] = []
    _fake_npm(monkeypatch, False, reloads)

    assert npm_provision.provision_npm_hosts(_nginx_tree(), config_dir) is True
    assert reloads == []


def test_a_guard_that_cannot_be_installed_fails_provisioning(config_dir, monkeypatch, capsys):
    reloads: list[str] = []
    _fake_npm(monkeypatch, None, reloads)

    assert npm_provision.provision_npm_hosts(_nginx_tree(), config_dir) is False
    assert "app hosts" in capsys.readouterr().err


def test_an_unusable_host_scheme_fails_provisioning_before_the_guard(
    config_dir, monkeypatch, capsys
):
    reloads: list[str] = []
    calls = _fake_npm(monkeypatch, True, reloads)

    tree = _nginx_tree(INGRESS_APP_DOMAIN="apps.example.com")
    assert npm_provision.provision_npm_hosts(tree, config_dir) is False
    assert calls == []
    assert "INGRESS_APP_DOMAIN" in capsys.readouterr().err


# ── platform cookies (doctor) ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("header", "covering"),
    [
        ("sid=abc; Path=/; Secure; HttpOnly", None),
        ("sid=abc; Domain=example.com; Path=/", "example.com"),
        ("sid=abc; domain=.EXAMPLE.com", "example.com"),
        ("sid=abc; Domain=apps.example.com", "apps.example.com"),
        ("sid=abc; Domain=chat.example.com", None),
        ("sid=abc; Domain=other.org", None),
        ("sid=abc; Domain=example.com; Domain=chat.example.com", None),
        ("sid=abc; Domain=chat.example.com; Domain=example.com", "example.com"),
        ("sid=abc; Domain=com", "com"),
    ],
)
def test_a_cookie_domain_covering_an_app_host_is_found(header, covering):
    found = edge_guard.covering_cookie(header, ["apps.example.com"])

    assert found == (("sid", covering) if covering else None)


def test_the_cookie_value_never_leaves_the_parser():
    found = edge_guard.covering_cookie(
        "KEYCLOAK_SESSION=secret-value-1234; Domain=example.com", ["apps.example.com"]
    )

    assert found == ("KEYCLOAK_SESSION", "example.com")
    assert "secret-value-1234" not in json.dumps(found)


def test_no_platform_service_is_configured_with_a_cookie_domain():
    """The identity provider, the forward-auth proxies and the core modules set host-only
    cookies: nothing in the core's Compose files or settings names a cookie domain."""
    pattern = re.compile(r"cookie[-_]?domain", re.IGNORECASE)
    found = []
    for path in sorted((REPO / "src").rglob("*")):
        if path.name not in ("docker-compose.yml", ".env.example") or not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                found.append(f"{path.relative_to(REPO)}:{number}")
    assert found == []
