"""`doctor edge_app_origin`: the edge's controls for Studio app hosts (security §4.1, E-20).

The bundled proxy must refuse writes whose `Origin` is an app host (lib/edge_guard.py),
and no platform cookie may carry a `Domain` attribute that covers an app host. Docker is
`FakeDocker`; the anonymous GETs go through the `http_get` probe.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from stack_helpers import NOW, FakeDocker, healthy_addon, healthy_core, ps_line

from lib import doctor, edge_guard
from lib.doctor import FAIL, PASS, SKIP, WARN, Probes

BASES = ["apps.example.com"]
SECRET_VALUE = "c2Vzc2lvbi12YWx1ZS1uZXZlci1zaG93bg"


def _nginx_stack(stack, **env: str) -> None:
    repo, config = stack["repo"], stack["config"]
    root = yaml.safe_load((repo / "src" / "docker-compose.yml").read_text(encoding="utf-8"))
    root["include"].append("./infra/nginx/docker-compose.yml")
    (repo / "src" / "docker-compose.yml").write_text(yaml.safe_dump(root), encoding="utf-8")
    fragment = repo / "src" / "infra" / "nginx" / "docker-compose.yml"
    fragment.parent.mkdir(parents=True, exist_ok=True)
    fragment.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "nginx-proxy-manager": {
                        "image": "example/image:1",
                        "profiles": ["nginx"],
                        "labels": {
                            "de.fidonis.module": "papaia-nginx",
                            "de.fidonis.role": "reverse-proxy",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    values = {
        "COMPOSE_PROFILES": "keycloak,oauth2-proxy,librechat-websearch,nginx",
        "REVERSE_PROXY_PROVIDER": "internal_nginx",
        "PAPAIA_HOST": "https://example.com",
        "AUTH_HOST": "https://auth.example.com",
        "NPM_ADMIN_HOST": "https://npm.example.com",
        "OIDC_ISSUER": "https://auth.example.com/realms/papaia",
        **env,
    }
    with (config / ".env").open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _guard(stack, bases: list[str] = BASES, *, refused: int = 0) -> None:
    config = stack["config"]
    for target, text in (
        (edge_guard.HTTP_TARGET, edge_guard.http_block(bases)),
        (edge_guard.SERVER_TARGET, edge_guard.server_block()),
    ):
        path = edge_guard.host_path(config, target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    if refused:
        log = edge_guard.host_path(config, edge_guard.AUDIT_LOG)
        log.parent.mkdir(parents=True, exist_ok=True)
        line = '{"format":"papaia.audit/1","time":"2026-11-23T10:15:00.042Z"}\n'
        log.write_text(line * refused, encoding="utf-8")


def _docker(proxy_state: str | None = "running") -> FakeDocker:
    lines = healthy_core() + healthy_addon()
    if proxy_state is not None:
        lines.append(
            ps_line(
                "papaia-nginx-proxy-manager-1",
                proxy_state,
                "Up 2 hours" if proxy_state == "running" else "Exited (1)",
                "nginx-proxy-manager",
                "papaia-nginx",
                "reverse-proxy",
            )
        )
    return FakeDocker(lines)


class _Web:
    """Answers per URL; records the edge address and URL of every GET."""

    def __init__(self, answers: dict[str, object]):
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    def __call__(self, address: str, url: str, ca_file: Path | None):
        self.calls.append((address, url))
        answer = self.answers.get(url, (200, [], None))
        if isinstance(answer, Exception):
            raise answer
        return answer


def _run(stack, web: _Web, docker: FakeDocker | None = None) -> doctor.CheckResult:
    report = doctor.run_checks(
        stack["config"],
        stack["repo"],
        run=docker or _docker(),
        probes=Probes(
            in_container=lambda: False,
            launchd_host=lambda: False,
            http_get=web,
            resolve=lambda host: doctor.RESOLVED,
            connect=lambda host, port: False,
        ),
        now=NOW,
    )
    return next(c for c in report.checks if c.name == "edge_app_origin")


def _sign_in_web(auth_cookie: str = "AUTH_SESSION_ID=x; Path=/realms/papaia/; HttpOnly"):
    return _Web(
        {
            "https://npm.example.com/": (
                302,
                ["_oauth2_proxy_npm_csrf=y; Path=/; HttpOnly"],
                "https://auth.example.com/realms/papaia/protocol/openid-connect/auth?x=1",
            ),
            "https://auth.example.com/realms/papaia/protocol/openid-connect/auth?x=1": (
                200,
                [auth_cookie],
                None,
            ),
            "https://auth.example.com/realms/papaia/account/": (
                302,
                [],
                "/realms/papaia/protocol/openid-connect/auth?x=1",
            ),
        }
    )


def test_passes_with_the_guard_in_place_and_only_host_only_cookies(stack):
    _nginx_stack(stack)
    _guard(stack, refused=3)
    web = _sign_in_web()

    check = _run(stack, web)

    assert check.status == PASS, check.summary
    assert "apps.example.com" in check.summary
    assert "3 write(s) from app hosts refused" in check.summary
    assert check.details["refused_writes"] == 3
    urls = [url for _, url in web.calls]
    assert "https://auth.example.com/" in urls
    assert "https://npm.example.com/" in urls
    assert "https://auth.example.com/realms/papaia/account/" in urls
    # The redirect to the sign-in page is followed: the identity provider's cookies.
    assert "https://auth.example.com/realms/papaia/protocol/openid-connect/auth?x=1" in urls
    # The bundled proxy is asked on this host's edge address, never through DNS.
    assert {address for address, _ in web.calls} == {"127.0.0.1"}


def test_a_platform_cookie_whose_domain_covers_the_app_hosts_fails(stack):
    _nginx_stack(stack)
    _guard(stack)
    web = _sign_in_web(f"KC_RESTART={SECRET_VALUE}; Domain=.example.com; Path=/")

    check = _run(stack, web)

    assert check.status == FAIL
    assert "KC_RESTART (Domain=example.com, set by auth.example.com)" in check.summary
    assert SECRET_VALUE not in check.summary
    assert SECRET_VALUE not in json.dumps(check.details)


def test_a_missing_guard_fails_and_names_the_command(stack):
    _nginx_stack(stack)
    web = _sign_in_web()

    check = _run(stack, web)

    assert check.status == FAIL
    assert "does not refuse writes from the app hosts" in check.summary
    assert "papaia-ctl npm-provision" in check.summary


def test_a_guard_for_other_app_hosts_fails(stack):
    _nginx_stack(stack, INGRESS_APP_DOMAIN="example-apps.org")
    _guard(stack, BASES)

    check = _run(stack, _sign_in_web())

    assert check.status == FAIL
    assert "lacks the current managed block" in check.summary


def test_an_unreachable_host_warns_and_is_named(stack):
    _nginx_stack(stack)
    _guard(stack)
    web = _sign_in_web()
    web.answers["https://npm.example.com/"] = ConnectionRefusedError("refused")

    check = _run(stack, web)

    assert check.status == WARN
    assert "npm.example.com: ConnectionRefusedError" in check.summary


def test_a_redirect_off_the_installation_is_not_followed(stack):
    _nginx_stack(stack)
    _guard(stack)
    web = _sign_in_web()
    web.answers["https://npm.example.com/"] = (302, [], "https://elsewhere.example.org/login")

    check = _run(stack, web)

    assert check.status == PASS
    assert all("elsewhere" not in url for _, url in web.calls)


def test_a_redirect_loop_stops_after_the_hop_limit(stack):
    _nginx_stack(stack)
    _guard(stack)
    web = _sign_in_web()
    web.answers["https://npm.example.com/"] = (302, [], "https://npm.example.com/")

    check = _run(stack, web)

    assert check.status == PASS
    loops = [url for _, url in web.calls if url == "https://npm.example.com/"]
    assert len(loops) == edge_guard.PROBE_MAX_HOPS + 1


def test_the_edge_address_follows_the_host_ip(stack):
    _nginx_stack(stack, INGRESS_HOST_IP="192.0.2.10")
    _guard(stack)
    web = _sign_in_web()

    _run(stack, web)

    assert {address for address, _ in web.calls} == {"192.0.2.10"}


def test_a_stopped_proxy_leaves_the_guard_unchecked(stack):
    _nginx_stack(stack)

    check = _run(stack, _sign_in_web(), docker=_docker("exited"))

    assert check.status == WARN
    assert "nginx-proxy-manager is exited" in check.summary


def test_an_external_proxy_is_reminded_to_refuse_the_writes_itself(stack):
    _nginx_stack(stack, REVERSE_PROXY_PROVIDER="external_proxy")
    web = _sign_in_web()

    check = _run(stack, web)

    assert check.status == WARN
    assert "external proxy must refuse writes from the app hosts" in check.summary
    # Behind an external proxy the host names are looked up as a browser would.
    assert ("auth.example.com", "https://auth.example.com/") in web.calls


def test_skips_without_a_proxy(stack):
    _nginx_stack(stack, REVERSE_PROXY_PROVIDER="no_proxy")

    check = _run(stack, _Web({}))

    assert check.status == SKIP


def test_skips_while_the_bundled_proxy_is_not_enabled(stack):
    check = _run(stack, _Web({}))

    assert check.status == SKIP
    assert check.summary == "the bundled proxy is not enabled"


def test_an_app_domain_inside_the_platform_domain_fails(stack):
    _nginx_stack(stack, INGRESS_APP_DOMAIN="apps.example.com")

    check = _run(stack, _Web({}))

    assert check.status == FAIL
    assert "INGRESS_APP_DOMAIN" in check.summary


def test_audit_lines_without_a_utc_time_warn(stack):
    _nginx_stack(stack)
    _guard(stack, refused=1)
    log = edge_guard.host_path(stack["config"], edge_guard.AUDIT_LOG)
    with log.open("a", encoding="utf-8") as handle:
        handle.write('{"format":"papaia.audit/1","time":".042Z"}\n')

    check = _run(stack, _sign_in_web())

    assert check.status == WARN
    assert "1 audit line(s) of the edge without a UTC time" in check.summary
