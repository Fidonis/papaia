"""Only the edge publishes ports; direct ports come from a generated override (BE-06, RE-21).

The base compose files publish the edge ports and nothing else but the loopback API of the
bundled proxy. A port of its own per service is a development mode (`no_proxy` or
`--allow-direct-port-access`), and only then does `setup` write
`overrides/docker-compose.direct-ports.override.yml`. A service with header identity,
`me-web` and every service of a module with `delegation` never get a port: `setup` and
`doctor` refuse direct port access while such a service is installed, and a `ports:` entry
of such a service in any mode.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from lib import common, deployment, direct_ports, doctor, published_ports

REPO = Path(__file__).resolve().parents[2]

CORE_SERVICES_WITHOUT_PORT = (
    "keycloak",
    "oauth2-proxy",
    "nginx-proxy-manager-auth",
    "papaia-manager",
    "librechat",
    "litellm",
    "localai",
    "qdrant",
    "qdrant-ingest",
)

ALL_PROFILES = "keycloak,oauth2-proxy,librechat,litellm,localai,manager,rag"


def _root(**extra: str) -> dict[str, str]:
    root = {
        "PAPAIA_HOST": "http://host.docker.internal",
        "REVERSE_PROXY_PROVIDER": "internal_nginx",
        "COMPOSE_PROJECT_NAME": "papaia-itest",
        "DOCKER_NETWORK": "papaia-itest-net",
        "COMPOSE_PROFILES": f"{ALL_PROFILES},nginx",
        "HOST_IP": "127.0.0.1",
    }
    root.update(extra)
    return root


NO_PROXY = {"REVERSE_PROXY_PROVIDER": "no_proxy", "COMPOSE_PROFILES": ALL_PROFILES}
ALLOW_DIRECT = {"REVERSE_PROXY_PROVIDER": "internal_nginx", "COMPOSE_PROFILES": ALL_PROFILES}
EXTERNAL = {"REVERSE_PROXY_PROVIDER": "external_proxy", "COMPOSE_PROFILES": ALL_PROFILES}


def _entry(service: str, **extra) -> dict:
    entry = {
        "id": f"{service}.web",
        "kind": "ui",
        "address": {"service": service, "port": 8000, "scheme": "http"},
        "identity": ["person"],
    }
    entry.update(extra)
    return entry


def _addon(
    tmp_path: Path, name: str, services: dict, exposes: list | None = None, **extra
) -> dict:
    path = tmp_path / "addons" / name
    path.mkdir(parents=True)
    manifest: dict = {"name": name, "version": "1.0.0", **extra}
    if exposes is not None:
        manifest["exposes"] = exposes
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (path / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": services}), encoding="utf-8"
    )
    return {"name": name, "path": str(path), "active": True}


def _install(tmp_path: Path, *addons: dict, **root: str) -> tuple[Path, dict[str, str]]:
    config = tmp_path / "config"
    config.mkdir()
    deployment.save(config, {"addons": list(addons)})
    values = _root(**root)
    common.atomic_write(config / ".env", "".join(f"{k}={v}\n" for k, v in values.items()))
    return config, values


def _ui_entry(host_key: str, **extra) -> dict:
    entry = {
        "id": f"{host_key}.web",
        "kind": "ui",
        "identity": ["person"],
        "ui": [{"id": "web", "host_key": host_key, "path": "/"}],
    }
    entry.update(extra)
    return entry


def _header_identity(tmp_path: Path) -> dict:
    # The web interface signs a person in from the header the edge sets; the MCP server
    # checks tokens itself and carries no marker.
    return _addon(
        tmp_path,
        "paperless",
        {"paperless": {"image": "x"}, "paperless-mcp": {"image": "x"}},
        [_ui_entry("paperless", header_identity=True), _entry("paperless-mcp")],
        integration={"nginx": [{"host_key": "paperless", "service": "paperless", "port": 8000}]},
    )


def _me_web(tmp_path: Path) -> dict:
    return _addon(tmp_path, "me", {"me-web": {"image": "x"}, "prefs": {"image": "x"}})


def _delegation(tmp_path: Path) -> dict:
    return _addon(
        tmp_path,
        "flow",
        {"flow-api": {"image": "x"}, "flow-worker": {"image": "x"}},
        [_entry("flow-api", delegation={"purposes": ["flow.run"]})],
    )


def _plain(tmp_path: Path) -> dict:
    return _addon(tmp_path, "wiki", {"wiki": {"image": "x"}}, [_entry("wiki")])


PROTECTED = {"header identity": _header_identity, "me-web": _me_web, "delegation": _delegation}


# ─────────────────────────────────────────────────────────────────────────
# base compose files
# ─────────────────────────────────────────────────────────────────────────


def _core_ports() -> dict[str, list]:
    found: dict[str, list] = {}
    for path in published_ports.compose_fragments(REPO):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (doc.get("services") or {}).items():
            if isinstance(body, dict) and body.get("ports"):
                found[name] = body["ports"]
    return found


def test_the_base_compose_files_publish_only_the_edge():
    ports = _core_ports()
    assert set(ports) == {published_ports.EDGE_SERVICE}
    edge = ports[published_ports.EDGE_SERVICE]
    assert [p for p in edge if p not in published_ports.EDGE_ENTRIES] == [
        "127.0.0.1:${NPM_API_LOCAL_PORT:-8181}:81"
    ]


@pytest.mark.parametrize("service", CORE_SERVICES_WITHOUT_PORT)
def test_a_core_service_publishes_no_port(service):
    assert service not in _core_ports()


def test_the_legacy_list_keeps_only_the_npm_api_and_the_link_gateway():
    services = {key[1] for key in published_ports.FROZEN_INVENTORY}
    assert services == {"nginx-proxy-manager", "link-gateway"}
    assert published_ports.lint(REPO) == []


# ─────────────────────────────────────────────────────────────────────────
# the override
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("values", "mode"),
    [({}, None), (EXTERNAL, None), (NO_PROXY, "no_proxy"), (ALLOW_DIRECT, direct_ports.ALLOW_FLAG)],
)
def test_direct_mode_follows_the_provider_and_the_bundled_proxy(values, mode):
    assert direct_ports.direct_mode(_root(**values)) == mode


@pytest.mark.parametrize("values", [{}, EXTERNAL])
def test_behind_a_proxy_no_override_is_written(tmp_path, values):
    config, root = _install(tmp_path, **values)
    (config / direct_ports.OVERRIDE).parent.mkdir(parents=True)
    (config / direct_ports.OVERRIDE).write_text("services: {}\n", encoding="utf-8")
    assert direct_ports.write(config, root) is None
    assert not (config / direct_ports.OVERRIDE).exists()


@pytest.mark.parametrize("values", [NO_PROXY, ALLOW_DIRECT])
def test_direct_port_access_writes_the_override(tmp_path, values):
    config, root = _install(tmp_path, _plain(tmp_path), **values)
    assert direct_ports.refusals(root, config, REPO) == []
    path = direct_ports.write(config, root)
    assert path == config / direct_ports.OVERRIDE
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# Generated by papaia-ctl setup")
    services = yaml.safe_load(text)["services"]
    assert services["keycloak"]["ports"] == ["${HOST_IP:-0.0.0.0}:${KEYCLOAK_EXT_PORT:-8110}:8443"]
    assert services["qdrant"]["ports"] == ["${HOST_IP:-127.0.0.1}:${QDRANT_EXT_PORT:-6333}:6333"]
    assert "nginx-proxy-manager-auth" not in services
    assert direct_ports.verify(config, root) == []


def test_the_override_covers_the_active_profiles_only(tmp_path):
    config, root = _install(
        tmp_path, REVERSE_PROXY_PROVIDER="no_proxy", COMPOSE_PROFILES="keycloak,librechat"
    )
    direct_ports.write(config, root)
    services = yaml.safe_load((config / direct_ports.OVERRIDE).read_text(encoding="utf-8"))
    assert set(services["services"]) == {"keycloak", "librechat"}


def test_doctor_reports_a_hand_edited_override(tmp_path):
    config, root = _install(tmp_path, **NO_PROXY)
    path = direct_ports.write(config, root)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(":8443", ":9443"), encoding="utf-8")
    findings = direct_ports.verify(config, root)
    assert len(findings) == 1 and "edited by hand" in findings[0]
    result = doctor.check_direct_ports(_ctx(config))
    assert result.status == doctor.FAIL and "edited by hand" in result.summary


def test_doctor_reports_an_override_with_a_recomputed_digest_but_another_port(tmp_path):
    config, root = _install(tmp_path, **NO_PROXY)
    path = direct_ports.write(config, root)
    body = direct_ports.render_body(root).replace(":8443", ":9443")
    digest = direct_ports._digest(body)
    path.write_text(f"# digest: sha256:{digest}\n{body}", encoding="utf-8")
    assert direct_ports.verify(config, root) == [
        f"{direct_ports.OVERRIDE} does not match the configuration; run setup again"
    ]


def test_doctor_reports_an_override_left_behind_the_edge(tmp_path):
    config, root = _install(tmp_path, **NO_PROXY)
    direct_ports.write(config, root)
    behind_edge = _root()
    common.atomic_write(config / ".env", "".join(f"{k}={v}\n" for k, v in behind_edge.items()))
    result = doctor.check_direct_ports(_ctx(config))
    assert result.status == doctor.FAIL and "edge proxy" in result.summary


def test_doctor_passes_a_generated_override(tmp_path):
    config, root = _install(tmp_path, **NO_PROXY)
    direct_ports.write(config, root)
    assert doctor.check_direct_ports(_ctx(config)).status == doctor.PASS


def test_doctor_passes_without_override_behind_the_edge(tmp_path):
    config, _ = _install(tmp_path)
    assert doctor.check_direct_ports(_ctx(config)).status == doctor.PASS


# ─────────────────────────────────────────────────────────────────────────
# services that never publish a port
# ─────────────────────────────────────────────────────────────────────────


def _ctx(config: Path) -> doctor.Context:
    from datetime import datetime, timezone

    from lib import status

    return doctor.Context(
        config,
        REPO,
        run=status.run_command,
        probes=doctor.Probes(),
        now=datetime.now(timezone.utc),
    )


@pytest.mark.parametrize("kind", sorted(PROTECTED))
@pytest.mark.parametrize("values", [NO_PROXY, ALLOW_DIRECT])
def test_direct_port_access_is_refused_for_a_protected_service(tmp_path, kind, values):
    config, root = _install(tmp_path, PROTECTED[kind](tmp_path), **values)
    found = direct_ports.refusals(root, config, REPO)
    assert len(found) == 1 and "direct port access" in found[0] and kind in found[0]
    result = doctor.check_addon_ports(_ctx(config))
    assert result.status == doctor.FAIL and kind in result.summary


@pytest.mark.parametrize("kind", sorted(PROTECTED))
def test_behind_the_edge_a_protected_service_is_fine(tmp_path, kind):
    config, root = _install(tmp_path, PROTECTED[kind](tmp_path))
    assert direct_ports.refusals(root, config, REPO) == []
    assert doctor.check_addon_ports(_ctx(config)).status == doctor.PASS


@pytest.mark.parametrize("address", ["127.0.0.1:8130:8130", "8130:8130"])
def test_a_protected_service_with_a_port_is_refused_behind_the_edge_too(tmp_path, address):
    addon = _addon(tmp_path, "me", {"me-web": {"image": "x", "ports": [address]}})
    config, root = _install(tmp_path, addon)
    found = direct_ports.refusals(root, config, REPO)
    assert len(found) == 1 and "me-web" in found[0] and address in found[0]
    assert doctor.check_addon_ports(_ctx(config)).status == doctor.FAIL


def _addon_override(config: Path, segment: str, text: str) -> None:
    folder = config / "overrides" / "addons"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"docker-compose.{segment}.override.yml").write_text(text, encoding="utf-8")


@pytest.mark.parametrize("segment", ["me", "me-ports"])
def test_a_port_from_an_add_on_override_is_refused_too(tmp_path, segment):
    # `addon start` hands docker compose the add-on's overrides as well: a port placed
    # there by hand publishes the service just as its own compose file would.
    config, root = _install(tmp_path, _me_web(tmp_path))
    _addon_override(config, segment, "services:\n  me-web:\n    ports: !override\n"
                    "      - 127.0.0.1:8130:8130\n")
    found = direct_ports.refusals(root, config, REPO)
    assert len(found) == 1 and "me-web" in found[0] and "127.0.0.1:8130:8130" in found[0]
    assert doctor.check_addon_ports(_ctx(config)).status == doctor.FAIL


def test_an_override_of_another_add_on_is_not_attributed(tmp_path):
    # `me-tools` is an add-on of its own: its override does not belong to `me`.
    tools = _addon(tmp_path, "me-tools", {"me-web": {"image": "x"}})
    config, root = _install(tmp_path, _me_web(tmp_path), tools)
    _addon_override(config, "me-tools", "services:\n  me-web:\n    ports: ['9000:9000']\n")
    found = direct_ports.refusals(root, config, REPO)
    assert len(found) == 1 and "'me-tools'" in found[0] and "9000:9000" in found[0]


def test_a_broken_add_on_override_is_refused(tmp_path):
    config, root = _install(tmp_path, _me_web(tmp_path))
    _addon_override(config, "me", "services: [\n")
    found = direct_ports.refusals(root, config, REPO)
    assert len(found) == 1 and "not valid YAML" in found[0]


def test_every_service_of_a_module_with_delegation_is_protected(tmp_path):
    config, _ = _install(tmp_path, _delegation(tmp_path))
    found = direct_ports.protected_services(config, REPO)
    assert {(p.service, p.reason) for p in found} == {
        ("flow-api", "module with delegation"),
        ("flow-worker", "module with delegation"),
    }


def test_header_identity_protects_the_service_of_the_entry_only(tmp_path):
    config, _ = _install(tmp_path, _header_identity(tmp_path))
    found = direct_ports.protected_services(config, REPO)
    assert [(p.service, p.reason) for p in found] == [("paperless", "header identity")]


def test_a_marker_that_names_no_service_protects_the_whole_module(tmp_path):
    addon = _addon(
        tmp_path, "paperless", {"paperless": {"image": "x"}, "paperless-mcp": {"image": "x"}},
        [_ui_entry("unknown", header_identity=True)],
    )
    config, _ = _install(tmp_path, addon)
    found = direct_ports.protected_services(config, REPO)
    assert {p.service for p in found} == {"paperless", "paperless-mcp"}


def test_a_marked_entry_with_an_address_protects_that_service(tmp_path):
    addon = _addon(
        tmp_path, "paperless", {"paperless": {"image": "x"}, "paperless-mcp": {"image": "x"}},
        [_entry("paperless-mcp", kind="rest", header_identity=True)],
    )
    config, _ = _install(tmp_path, addon)
    found = direct_ports.protected_services(config, REPO)
    assert [p.service for p in found] == ["paperless-mcp"]


def test_a_malformed_header_identity_marker_is_refused(tmp_path):
    addon = _addon(
        tmp_path, "paperless", {"paperless": {"image": "x"}},
        [_entry("paperless", header_identity="yes")],
    )
    config, root = _install(tmp_path, addon, **NO_PROXY)
    found = direct_ports.refusals(root, config, REPO)
    assert len(found) == 1 and "header_identity must be true or false" in found[0]


def test_an_inactive_addon_is_not_counted(tmp_path):
    addon = _me_web(tmp_path)
    addon["active"] = False
    config, root = _install(tmp_path, addon, **NO_PROXY)
    assert direct_ports.refusals(root, config, REPO) == []
