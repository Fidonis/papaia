"""The compose ratchet on published host ports.

Only the edge proxy publishes ports, bound to HOST_IP through the edge port variables.
Every other `ports:` entry of the core stands on the legacy list in
`security/published-ports.yaml`, a frozen inventory: entries are only ever removed, so the
set of published ports can shrink but never grow. These tests run the check against this
checkout and against modified copies of it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml
from test_link import ENV, split
from test_topology import ALL_PROFILES

from lib import link, published_ports

REPO = Path(__file__).resolve().parents[2]


def _copy(tmp_path: Path) -> Path:
    """A copy of what the check reads: the compose fragments and the legacy list."""
    dest = tmp_path / "repo"
    shutil.copytree(REPO / "src", dest / "src", ignore=shutil.ignore_patterns(".env"))
    shutil.copytree(REPO / "security", dest / "security")
    # The generated exception names the module that writes it.
    (dest / "tools" / "lib").mkdir(parents=True)
    shutil.copyfile(REPO / "tools" / "lib" / "link.py", dest / "tools" / "lib" / "link.py")
    return dest


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _save(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _set_ports(repo: Path, rel: str, service: str, ports: list | None) -> None:
    path = repo / rel
    doc = _load(path)
    if ports is None:
        doc["services"][service].pop("ports", None)
    else:
        doc["services"][service]["ports"] = ports
    _save(path, doc)


def _drop_entry(repo: Path, service: str) -> None:
    path = repo / published_ports.ALLOW_LIST
    doc = _load(path)
    doc["entries"] = [e for e in doc["entries"] if e["service"] != service]
    _save(path, doc)


def _add_entry(repo: Path, entry: dict) -> None:
    path = repo / published_ports.ALLOW_LIST
    doc = _load(path)
    doc["entries"].append(entry)
    _save(path, doc)


NGINX = "src/infra/nginx/docker-compose.yml"
# The one compose entry left on the legacy list: the NPM API on loopback.
LEGACY = "nginx-proxy-manager"
LEGACY_PORT = "127.0.0.1:${NPM_API_LOCAL_PORT:-8181}:81"


def _set_legacy(repo: Path, ports: list) -> None:
    """The edge service's ports: the edge entries, then `ports` instead of the NPM API."""
    _set_ports(repo, NGINX, LEGACY, [*published_ports.EDGE_ENTRIES, *ports])


# ─────────────────────────────────────────────────────────────────────────
# this checkout
# ─────────────────────────────────────────────────────────────────────────


def test_this_checkout_publishes_nothing_beyond_the_edge_and_the_legacy_list():
    assert published_ports.lint(REPO) == []


def test_the_edge_publishes_its_ports_on_host_ip_through_the_edge_variables():
    doc = _load(REPO / NGINX)
    ports = doc["services"][published_ports.EDGE_SERVICE]["ports"]
    for entry in published_ports.EDGE_ENTRIES:
        assert entry in ports
    joined = "\n".join(published_ports.EDGE_ENTRIES)
    assert "INGRESS_HTTP_EXT_PORT:-80}:80" in joined
    assert "INGRESS_HTTPS_EXT_PORT:-443}:443" in joined
    assert "HOST_IP" in joined
    # The fixed bindings of earlier releases are gone.
    assert "80:80" not in ports and "443:443" not in ports


def test_the_edge_variables_are_documented_in_the_root_env_example():
    example = (REPO / "src" / ".env.example").read_text(encoding="utf-8")
    for key in ("INGRESS_HTTP_EXT_PORT=80", "INGRESS_HTTPS_EXT_PORT=443", "INGRESS_HOST_IP="):
        assert f"\n{key}\n" in example


def test_the_npm_api_stays_on_loopback():
    entries = {e.service: e for e in published_ports.load_allow_list(REPO)}
    npm = entries["nginx-proxy-manager"]
    assert (npm.variable, npm.target, npm.bind) == ("NPM_API_LOCAL_PORT", 81, "127.0.0.1")


def test_the_legacy_list_is_exactly_the_frozen_inventory():
    """List and inventory move together: an entry leaves both in the same change, so a
    port that comes back needs a visible growth of the inventory in the code."""
    keys = {e.key for e in published_ports.load_allow_list(REPO)}
    assert keys == published_ports.FROZEN_INVENTORY


def test_every_legacy_entry_names_its_reason_and_its_removal():
    for entry in published_ports.load_allow_list(REPO):
        assert entry.reason.strip(), entry.service
        assert entry.removed_by.strip(), entry.service
        assert (REPO / entry.file).is_file(), entry.file


def test_the_link_gateway_is_the_only_generated_exception():
    generated = [e for e in published_ports.load_allow_list(REPO) if e.source == "generated"]
    assert [(e.service, e.bind) for e in generated] == [("link-gateway", "node-address")]


def test_the_generated_link_port_is_covered_by_the_exception():
    plan = link.plan(split(), ALL_PROFILES, ENV)
    override = link.gateway_override(plan, split().nodes["edge"], "/srv/papaia-node/config")
    service = override["services"][link.GATEWAY_SERVICE]
    allow = published_ports.load_allow_list(REPO)
    assert published_ports.check_generated(link.GATEWAY_SERVICE, service["ports"], allow) == []


def test_a_generated_port_of_another_service_is_refused():
    allow = published_ports.load_allow_list(REPO)
    found = published_ports.check_generated("librechat", ["10.0.1.10:7443:7443"], allow)
    assert found and "librechat" in found[0]


def test_a_generated_link_port_on_a_bracketed_ipv6_address_is_covered():
    allow = published_ports.load_allow_list(REPO)
    ports = ["[fd00::1]:7443:7443"]
    assert published_ports.check_generated(link.GATEWAY_SERVICE, ports, allow) == []


def test_a_generated_link_port_on_a_host_name_is_refused():
    allow = published_ports.load_allow_list(REPO)
    found = published_ports.check_generated(link.GATEWAY_SERVICE, ["[edge]:7443:7443"], allow)
    assert found and "IP bind address" in found[0]


def test_a_generated_link_port_on_another_container_port_is_refused():
    allow = published_ports.load_allow_list(REPO)
    found = published_ports.check_generated(link.GATEWAY_SERVICE, ["10.0.1.10:7443:22"], allow)
    assert found


# ─────────────────────────────────────────────────────────────────────────
# the ratchet
# ─────────────────────────────────────────────────────────────────────────


def test_a_new_port_on_a_service_without_one_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    searxng = "src/services/searxng/docker-compose.yml"
    _set_ports(repo, searxng, "searxng", ["127.0.0.1:${X:-8888}:8080"])
    found = published_ports.lint(repo)
    assert len(found) == 1 and "searxng" in found[0]


def test_a_second_port_on_a_listed_service_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_legacy(repo, [LEGACY_PORT, "127.0.0.1:${NPM_ALT:-9000}:9000"])
    found = published_ports.lint(repo)
    assert len(found) == 1 and LEGACY in found[0] and "9000" in found[0]


def test_a_port_in_a_compose_file_outside_the_include_list_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _save(
        repo / "src" / "ai" / "newcomer" / "docker-compose.yml",
        {"services": {"newcomer": {"image": "busybox", "ports": ["127.0.0.1:${N:-1}:1"]}}},
    )
    found = published_ports.lint(repo)
    assert len(found) == 1 and "newcomer" in found[0]


@pytest.mark.parametrize(
    "service",
    ["keycloak", "oauth2-proxy", "papaia-manager", "librechat", "litellm", "localai", "qdrant"],
)
def test_a_removed_core_port_that_comes_back_fails(tmp_path: Path, service: str):
    """The core services moved behind the edge: none of them may publish again."""
    repo = _copy(tmp_path)
    for path in published_ports.compose_fragments(repo):
        doc = _load(path)
        if service in (doc.get("services") or {}):
            doc["services"][service]["ports"] = ["${HOST_IP:-0.0.0.0}:${X_EXT_PORT}:1234"]
            _save(path, doc)
            break
    else:
        pytest.fail(f"no fragment declares {service}")
    found = published_ports.lint(repo)
    assert len(found) == 1 and service in found[0]


def test_a_long_syntax_port_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_legacy(repo, [{"target": 81, "published": "${NPM_API_LOCAL_PORT}"}])
    found = published_ports.lint(repo)
    assert any(LEGACY in f and "short syntax" in f for f in found)


def test_a_listed_port_moved_to_all_interfaces_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_legacy(repo, ["0.0.0.0:${NPM_API_LOCAL_PORT:-8181}:81"])
    found = published_ports.lint(repo)
    assert any(LEGACY in f and "0.0.0.0" in f for f in found)


def test_a_listed_port_with_a_fixed_host_port_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_legacy(repo, ["127.0.0.1:8181:81"])
    found = published_ports.lint(repo)
    assert any(LEGACY in f and "8181:81" in f for f in found)


def test_a_listed_port_without_a_bind_address_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_legacy(repo, ["${NPM_API_LOCAL_PORT:-8181}:81"])
    found = published_ports.lint(repo)
    assert any(LEGACY in f for f in found)


def test_a_listed_port_in_another_file_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_legacy(repo, [])
    other = "src/infra/oauth2-proxy/docker-compose.yml"
    doc = _load(repo / other)
    doc["services"][LEGACY] = {"image": "x", "ports": [LEGACY_PORT]}
    _save(repo / other, doc)
    found = published_ports.lint(repo)
    assert any(other in f and LEGACY in f for f in found)


def test_removing_a_legacy_entry_fails_while_the_port_remains(tmp_path: Path):
    repo = _copy(tmp_path)
    _drop_entry(repo, LEGACY)
    found = published_ports.lint(repo)
    assert len(found) == 2 and all(LEGACY in f for f in found)
    assert any("neither an edge port nor on the legacy list" in f for f in found)
    assert any("FROZEN_INVENTORY" in f for f in found)


def _shrink_inventory(monkeypatch: pytest.MonkeyPatch, service: str) -> None:
    """The code side of removing a legacy port: its key leaves FROZEN_INVENTORY."""
    shrunk = frozenset(k for k in published_ports.FROZEN_INVENTORY if k[1] != service)
    monkeypatch.setattr(published_ports, "FROZEN_INVENTORY", shrunk)


def test_removing_entry_and_port_without_shrinking_the_inventory_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _drop_entry(repo, LEGACY)
    _set_legacy(repo, [])
    found = published_ports.lint(repo)
    assert len(found) == 1
    assert LEGACY in found[0] and "FROZEN_INVENTORY" in found[0]


def test_removing_a_legacy_entry_and_re_adding_the_port_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = _copy(tmp_path)
    _drop_entry(repo, LEGACY)
    _set_legacy(repo, [])
    _shrink_inventory(monkeypatch, LEGACY)
    # Entry, port and inventory key removed together: the inventory shrank.
    assert published_ports.lint(repo) == []
    _set_legacy(repo, [LEGACY_PORT])
    found = published_ports.lint(repo)
    assert len(found) == 1 and LEGACY in found[0]


def test_re_adding_a_removed_entry_and_its_port_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Once a port is gone from list, compose and inventory, putting the list entry and
    the port back is not enough: the inventory in the code would have to grow too."""
    repo = _copy(tmp_path)
    entry = next(
        e for e in _load(repo / published_ports.ALLOW_LIST)["entries"] if e["service"] == LEGACY
    )
    _drop_entry(repo, LEGACY)
    _set_legacy(repo, [])
    _shrink_inventory(monkeypatch, LEGACY)
    assert published_ports.lint(repo) == []
    _add_entry(repo, entry)
    _set_legacy(repo, [LEGACY_PORT])
    found = published_ports.lint(repo)
    assert any("frozen inventory" in f and LEGACY in f for f in found)


def test_adding_a_new_entry_to_the_list_fails(tmp_path: Path):
    """A port that was never published does not get onto the list by editing it."""
    repo = _copy(tmp_path)
    _add_entry(
        repo,
        {
            "service": "searxng",
            "source": "compose",
            "file": "src/services/searxng/docker-compose.yml",
            "variable": "SEARXNG_EXT_PORT",
            "target": 8080,
            "bind": "127.0.0.1",
            "reason": "debugging",
            "removed_by": "never",
        },
    )
    _set_ports(repo, "src/services/searxng/docker-compose.yml", "searxng", [
        "127.0.0.1:${SEARXNG_EXT_PORT:-8888}:8080",
    ])
    found = published_ports.lint(repo)
    assert any("frozen inventory" in f and "searxng" in f for f in found)


def test_a_legacy_entry_without_its_port_is_stale(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_legacy(repo, [])
    found = published_ports.lint(repo)
    assert len(found) == 1 and LEGACY in found[0] and "remove" in found[0]


def test_the_fixed_edge_ports_fail(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_ports(repo, NGINX, published_ports.EDGE_SERVICE, [
        "80:80",
        "443:443",
        "127.0.0.1:${NPM_API_LOCAL_PORT:-8181}:81",
    ])
    found = published_ports.lint(repo)
    assert any("80:80" in f for f in found)
    assert any("443:443" in f for f in found)


def test_an_edge_port_on_all_interfaces_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_ports(repo, NGINX, published_ports.EDGE_SERVICE, [
        "0.0.0.0:${INGRESS_HTTP_EXT_PORT:-80}:80",
        published_ports.EDGE_ENTRIES[1],
        "127.0.0.1:${NPM_API_LOCAL_PORT:-8181}:81",
    ])
    found = published_ports.lint(repo)
    assert found and all(published_ports.EDGE_SERVICE in f for f in found)


def test_a_third_edge_port_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_ports(repo, NGINX, published_ports.EDGE_SERVICE, [
        *published_ports.EDGE_ENTRIES,
        "127.0.0.1:${NPM_API_LOCAL_PORT:-8181}:81",
        "${HOST_IP:-0.0.0.0}:${INGRESS_ALT_PORT:-8443}:8443",
    ])
    found = published_ports.lint(repo)
    assert len(found) == 1 and "8443" in found[0]


def test_a_static_link_gateway_port_fails(tmp_path: Path):
    """The link gateway's port exists only in the generated override of a node."""
    repo = _copy(tmp_path)
    _set_ports(repo, "src/infra/link-gateway/docker-compose.yml", "link-gateway", [
        "${HOST_IP:-0.0.0.0}:${LINK_PORT:-7443}:7443",
    ])
    found = published_ports.lint(repo)
    assert len(found) == 1 and "link-gateway" in found[0]


def test_the_edge_ports_in_another_fragment_fail(tmp_path: Path):
    """Compose merges services of the same name: a second fragment declaring the edge
    service must not add edge publications unnoticed."""
    repo = _copy(tmp_path)
    other = "src/infra/oauth2-proxy/docker-compose.yml"
    doc = _load(repo / other)
    doc["services"][published_ports.EDGE_SERVICE] = {
        "image": "x",
        "ports": list(published_ports.EDGE_ENTRIES),
    }
    _save(repo / other, doc)
    found = published_ports.lint(repo)
    assert len(found) == 2
    assert all(other in f and published_ports.EDGE_SERVICE in f for f in found)


def test_an_edge_port_published_twice_fails(tmp_path: Path):
    repo = _copy(tmp_path)
    _set_ports(repo, NGINX, published_ports.EDGE_SERVICE, [
        *published_ports.EDGE_ENTRIES,
        published_ports.EDGE_ENTRIES[0],
        "127.0.0.1:${NPM_API_LOCAL_PORT:-8181}:81",
    ])
    found = published_ports.lint(repo)
    assert len(found) == 1 and "more than once" in found[0]


def test_host_networking_on_a_core_service_fails(tmp_path: Path):
    """A service on the host network publishes every port it listens on."""
    repo = _copy(tmp_path)
    searxng = "src/services/searxng/docker-compose.yml"
    doc = _load(repo / searxng)
    doc["services"]["searxng"]["network_mode"] = "host"
    _save(repo / searxng, doc)
    found = published_ports.lint(repo)
    assert len(found) == 1 and "searxng" in found[0] and "network_mode" in found[0]


# ─────────────────────────────────────────────────────────────────────────
# the list itself is validated
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda e: e.update(extra="x"), "unknown field"),
        (lambda e: e.pop("reason"), "missing field"),
        (lambda e: e.update(target="8443"), "target"),
        (lambda e: e.update(target=70000), "target"),
        (lambda e: e.update(bind="0.0.0.0"), "bind"),
        (lambda e: e.update(source="runtime"), "source"),
        (lambda e: e.update(reason=""), "reason"),
        (lambda e: e.update(reason="x" * 1001), "reason"),
        (lambda e: e.update(variable="lower-case"), "variable"),
        (lambda e: e.update(file="../outside.yml"), "file"),
    ],
)
def test_a_malformed_entry_is_refused(tmp_path: Path, change, message):
    repo = _copy(tmp_path)
    path = repo / published_ports.ALLOW_LIST
    doc = _load(path)
    entry = next(e for e in doc["entries"] if e["service"] == LEGACY)
    change(entry)
    _save(path, doc)
    with pytest.raises(published_ports.AllowListError, match=message):
        published_ports.load_allow_list(repo)
    found = published_ports.lint(repo)
    assert len(found) == 1 and message in found[0]


def test_an_unknown_top_level_field_is_refused(tmp_path: Path):
    repo = _copy(tmp_path)
    path = repo / published_ports.ALLOW_LIST
    doc = _load(path)
    doc["extra"] = True
    _save(path, doc)
    with pytest.raises(published_ports.AllowListError, match="unknown field"):
        published_ports.load_allow_list(repo)


def test_a_duplicate_entry_is_refused(tmp_path: Path):
    repo = _copy(tmp_path)
    path = repo / published_ports.ALLOW_LIST
    doc = _load(path)
    doc["entries"].append(dict(next(e for e in doc["entries"] if e["service"] == LEGACY)))
    _save(path, doc)
    with pytest.raises(published_ports.AllowListError, match="duplicate"):
        published_ports.load_allow_list(repo)


def test_a_missing_list_is_refused(tmp_path: Path):
    repo = _copy(tmp_path)
    (repo / published_ports.ALLOW_LIST).unlink()
    found = published_ports.lint(repo)
    assert len(found) == 1 and str(published_ports.ALLOW_LIST) in found[0]
