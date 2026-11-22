"""Published ports of the rendered core compose, per proxy provider and module set.

`setup` runs against a copy of this checkout, then `docker compose config` renders the
project the way `start` assembles it. Behind a proxy the published ports are the edge
ports plus the legacy list in `security/published-ports.yaml` (the NPM API on loopback),
and the edge -- present only with the bundled proxy -- listens on HOST_IP with the edge
port variables. Only `no_proxy` publishes the ports of the core services, through the
generated direct-ports override.

Rendering needs the Docker CLI with Compose. Without it the test skips, except in CI,
where PAPAIA_REQUIRE_GOLDEN_COMPOSE is set and a missing Compose fails.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from install_helpers import Installation

from lib import common, direct_ports, envtree, published_ports

REPO = Path(__file__).resolve().parents[2]
REQUIRE_COMPOSE = os.environ.get("PAPAIA_REQUIRE_GOLDEN_COMPOSE") == "1"

HOST_IP = "127.0.0.1"
# Not the defaults: the rendered ports must come from the variables.
EDGE_HTTP = "59800"
EDGE_HTTPS = "59801"

PROVIDERS = ("internal_nginx", "external_proxy", "no_proxy")

MODULE_SETS: dict[str, list[str]] = {
    "default": [],
    "full": [
        "--enable-web-search=true",
        "--enable-local-ai=true",
        "--localai-variant=cpu",
        "--enable-manager=true",
        "--enable-rag=true",
        "--enable-voice=true",
        "--voice-variant=cpu",
        "--enable-knowledge-map=true",
        "--enable-smtp=true",
        "--smtp-host=smtp.example.org",
        "--smtp-port=587",
        "--smtp-security=starttls",
        "--smtp-no-auth",
        "--smtp-from=noreply@example.org",
    ],
}

_SHIPPED_HOST_IDS = {"UID": "1000", "GID": "1000", "DOCKER_GID": "999"}


def _have_compose() -> bool:
    if shutil.which("docker") is None:
        return False
    done = subprocess.run(
        ["docker", "compose", "version", "--short"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return done.returncode == 0


def _set_root_values(config: Path, values: dict[str, str]) -> None:
    """Edit the root .env the way an operator does: replace the line of each key."""
    path = config / ".env"
    text = path.read_text(encoding="utf-8")
    for key, value in values.items():
        pattern = re.compile(rf"^{key}=.*$", re.MULTILINE)
        assert pattern.search(text), f"{key} is missing from the generated root .env"
        text = pattern.sub(f"{key}={value}", text)
    path.write_text(text, encoding="utf-8")


def _render(inst: Installation) -> dict:
    envtree.materialize_core_env(inst.config, inst.repo)
    files = ["-f", str(inst.repo / "src" / "docker-compose.yml")]
    for override in sorted((inst.config / "overrides").glob("docker-compose.*.override.yml")):
        files += ["-f", str(override)]
    done = subprocess.run(
        [
            "docker",
            "compose",
            *files,
            "--env-file",
            str(inst.repo / "src" / ".env"),
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, **_SHIPPED_HOST_IDS},
    )
    if done.returncode != 0:
        pytest.fail(f"docker compose config failed:\n{done.stderr}")
    return json.loads(done.stdout)


def _module_env(config: Path, entry: published_ports.AllowEntry) -> dict[str, str]:
    """What compose interpolates the entry's fragment with: the root .env merged with
    the .env of the fragment's directory."""
    module_dir = Path(entry.file).parent.relative_to("src")
    env = common.parse_env_file(config / ".env")
    env.update(common.parse_env_file(config / module_dir / ".env"))
    return env


@pytest.mark.parametrize("modules", sorted(MODULE_SETS))
@pytest.mark.parametrize("provider", PROVIDERS)
def test_rendered_ports_are_the_edge_plus_the_legacy_list_or_the_direct_ports(
    tmp_path: Path, provider: str, modules: str
) -> None:
    if not _have_compose():
        if REQUIRE_COMPOSE:
            pytest.fail("docker compose is required to render the core project")
        pytest.skip("docker compose is not available")

    inst = Installation(
        tmp_path,
        [
            "--app-host=https://papaia.example.org",
            f"--reverse-proxy-provider={provider}",
            f"--host-ip={HOST_IP}",
            *MODULE_SETS[modules],
        ],
    )
    inst.setup(*inst.flags)
    _set_root_values(
        inst.config, {"INGRESS_HTTP_EXT_PORT": EDGE_HTTP, "INGRESS_HTTPS_EXT_PORT": EDGE_HTTPS}
    )
    services = _render(inst)["services"]

    allow = {
        (e.service, e.target): e
        for e in published_ports.load_allow_list(REPO)
        if e.source == "compose"
    }
    direct = {
        (p.service, p.target): p
        for p in direct_ports.CORE_DIRECT_PORTS
        if provider == "no_proxy"
    }
    edge = published_ports.EDGE_SERVICE
    edge_seen: set[tuple[int, str, str]] = set()
    direct_seen: set[str] = set()
    for name, body in services.items():
        for port in body.get("ports") or []:
            target, published, host_ip = port["target"], str(port["published"]), port["host_ip"]
            if name == edge and target in (80, 443):
                edge_seen.add((target, published, host_ip))
                continue
            if (name, target) in direct:
                assert host_ip == HOST_IP, f"{provider}/{modules}: '{name}' binds {host_ip}"
                direct_seen.add(name)
                continue
            entry = allow.get((name, target))
            assert entry is not None, (
                f"{provider}/{modules}: '{name}' publishes {host_ip}:{published}->{target},"
                " which is neither an edge port nor on the legacy list"
            )
            expected_ip = HOST_IP if entry.bind == "HOST_IP" else entry.bind
            assert host_ip == expected_ip, f"{provider}/{modules}: '{name}' binds {host_ip}"
            value = _module_env(inst.config, entry).get(entry.variable, "")
            if value:
                assert published == value, (
                    f"{provider}/{modules}: '{name}' publishes {published}, "
                    f"{entry.variable} is {value}"
                )

    if provider == "no_proxy":
        # Direct ports only for the services of the active profiles, Keycloak among them.
        assert "keycloak" in direct_seen
        assert direct_seen == {
            p.service for p in direct_ports.CORE_DIRECT_PORTS if p.service in services
        }
    else:
        assert not direct_seen
    if provider == "internal_nginx":
        assert edge in services
        assert edge_seen == {(80, EDGE_HTTP, HOST_IP), (443, EDGE_HTTPS, HOST_IP)}
    else:
        assert edge not in services
        assert not edge_seen
    published = {
        str(p["published"]) for body in services.values() for p in body.get("ports") or []
    }
    # Nothing takes 80 or 443 of the host: a second stack runs next to a busy one.
    assert not published & {"80", "443"}


def test_the_edge_binds_its_own_address_when_set(tmp_path: Path) -> None:
    """INGRESS_HOST_IP overrides HOST_IP for the edge only: on a node of a distributed
    installation the edge listens on the node address while the legacy ports stay on
    loopback."""
    if not _have_compose():
        if REQUIRE_COMPOSE:
            pytest.fail("docker compose is required to render the core project")
        pytest.skip("docker compose is not available")

    inst = Installation(
        tmp_path,
        [
            "--app-host=https://papaia.example.org",
            "--reverse-proxy-provider=internal_nginx",
            f"--host-ip={HOST_IP}",
        ],
    )
    inst.setup(*inst.flags)
    _set_root_values(inst.config, {"INGRESS_HOST_IP": "192.0.2.10"})
    services = _render(inst)["services"]

    edge = services[published_ports.EDGE_SERVICE]["ports"]
    assert {(p["target"], p["host_ip"]) for p in edge} == {
        (80, "192.0.2.10"),
        (443, "192.0.2.10"),
        (81, "127.0.0.1"),
    }
    # Keycloak sits behind the edge: no port of its own, also not on loopback.
    assert not services["keycloak"].get("ports")
