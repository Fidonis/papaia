"""Module selection checks of `addon install|start|uninstall` (PLT-31, PLT-54, OPS-02):
no two servers under one address, soft dependencies (`requires.addons` with
`optional: true`), Data before Studio, Paperless only with its gate, and what
`addon uninstall` leaves for the realm and the proxy to remove."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pytest
import yaml

from lib import catalog, cli_addon, compat, npm_provision, uninstall_journal
from lib import realm_sync as rs
from tests.realm_fake import FakeRealm
from tests.test_catalog import (
    FIXTURES,
    NOW,
    REPO,
    ROOT_ENV,
    _install,
    _install_args,
    _unchanged_after,
    _write_env,
)
from tests.test_realm_sync import DELEGATION, _flow, _full_plan, _plan, _studio
from tests.test_realm_sync import _paperless as _paperless_module

ADDON_PAPERLESS = Path(__file__).parent / "fixtures" / "addon-paperless"


def _manifest_copy(target: Path, fixture: Path, **changes) -> Path:
    shutil.copytree(fixture, target)
    manifest = yaml.safe_load((target / "papaia-app.yaml").read_text())
    manifest.update(changes)
    (target / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    return target


def _err(capsys) -> str:
    return capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────
# PLT-54: no two servers under one address
# ─────────────────────────────────────────────────────────────────────────


def _same_audience(tmp_path: Path) -> Path:
    """An add-on `other` whose tool server serves the audience of the probe."""
    other = _manifest_copy(tmp_path / "addons" / "other", FIXTURES / "addon-probe", name="other")
    manifest = yaml.safe_load((other / "papaia-app.yaml").read_text())
    manifest["exposes"][0].update(id="other.echo", address={"service": "other-mcp", "port": 8080})
    (other / "papaia-app.yaml").write_text(yaml.safe_dump(manifest))
    (other / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": {"other-mcp": {"image": "example.invalid/other:1.0.0"}}})
    )
    return other


def test_a_duplicate_audience_aborts_the_install(tmp_path, capsys):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    catalog.render(config_dir, REPO, now=NOW)
    other = _same_audience(tmp_path)

    def run() -> None:
        assert cli_addon.cmd_addon_install(_install_args(config_dir, "other", other)) == 2

    _unchanged_after(config_dir, run)
    err = _err(capsys)
    assert "audience 'mcp-probe' is served by probe/probe-mcp and other/other-mcp" in err
    assert not (config_dir / "addons" / "other").exists()  # refused before seeding
    catalog.render(config_dir, REPO, now=NOW)


def test_a_duplicate_audience_is_refused_without_an_identity_provider(tmp_path, capsys):
    """The catalog needs an https issuer; the address check does not wait for one."""
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    _write_env(config_dir / ".env", {"COMPOSE_PROFILES": "rag"})
    assert catalog.skip_reason(config_dir, REPO) is not None
    other = _same_audience(tmp_path)
    before = (config_dir / "deployment.yaml").read_bytes()

    assert cli_addon.cmd_addon_install(_install_args(config_dir, "other", other)) == 2
    assert "audience 'mcp-probe'" in _err(capsys)
    assert (config_dir / "deployment.yaml").read_bytes() == before


def test_qdrant_next_to_the_rag_profile_is_refused_on_install_and_start(tmp_path, capsys):
    """PLT-54-A1: the profile `rag` runs Qdrant; an add-on with the same servers is
    refused and the catalog keeps exactly one Qdrant entry."""
    config_dir = _install(tmp_path, "rag", [])
    catalog.render(config_dir, REPO, now=NOW)
    qdrant = tmp_path / "addons" / "qdrant"
    shutil.copytree(FIXTURES / "addon-qdrant", qdrant)

    def install() -> None:
        assert cli_addon.cmd_addon_install(_install_args(config_dir, "qdrant", qdrant)) == 2

    _unchanged_after(config_dir, install)
    err = _err(capsys)
    assert "service name 'qdrant' is used by the core and qdrant" in err
    assert "service name 'qdrant-mcp' is used by the core and qdrant" in err

    # Registered by an older core that did not check: `addon start` refuses it.
    deployed = yaml.safe_load((config_dir / "deployment.yaml").read_text())
    deployed.setdefault("addons", []).append(
        {"name": "qdrant", "path": str(qdrant), "active": True, "state": "stopped"}
    )
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump(deployed))
    args = argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(REPO), name="qdrant", force=True,
        no_keycloak=True,
    )

    def start() -> None:
        assert cli_addon.cmd_addon_start(args) == 2

    _unchanged_after(config_dir, start)
    assert "service name 'qdrant' is used by the core and qdrant" in _err(capsys)
    services = json.loads((config_dir / "platform" / "services.json").read_text())["services"]
    assert [s["provider"] for s in services if s["id"].startswith("qdrant")] == ["core:rag"]


def test_the_catalog_of_a_valid_installation_has_no_duplicates(tmp_path):
    """PLT-54-A2: no catalog id, audience or service name twice."""
    config_dir = _install(
        tmp_path, "rag",
        [("addon-probe", "probe", "running"), ("addon-console", "papaia-flow", "running")],
    )
    deployed = yaml.safe_load((config_dir / "deployment.yaml").read_text())
    for name in ("probe", "papaia-flow"):
        assert catalog.conflicts(config_dir, REPO, deployed, name) == []
    catalog.render(config_dir, REPO, now=NOW)
    services = json.loads((config_dir / "platform" / "services.json").read_text())["services"]
    ids = [s["id"] for s in services]
    audiences = [s["audience"] for s in services if "audience" in s]
    assert len(ids) == len(set(ids))
    assert len(audiences) == len(set(audiences))


def test_only_conflicts_of_the_addon_in_question_are_reported(tmp_path):
    config_dir = _install(tmp_path, "rag", [("addon-probe", "probe", "running")])
    deployed = yaml.safe_load((config_dir / "deployment.yaml").read_text())
    other = _same_audience(tmp_path)
    deployed["addons"].append({"name": "other", "path": str(other), "active": True})
    assert catalog.conflicts(config_dir, REPO, deployed, "unrelated") == []
    assert catalog.conflicts(config_dir, REPO, deployed, "probe")


# ─────────────────────────────────────────────────────────────────────────
# requires.addons with optional: true
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("data", compat.Requirement("data")),
        ({"id": "data", "optional": True}, compat.Requirement("data", None, True)),
        ({"name": "data", "version": ">=0.1.0"}, compat.Requirement("data", ">=0.1.0")),
    ],
)
def test_requirements_are_read_with_name_or_id_and_optional(entry, expected):
    assert compat.addon_requirements({"requires": {"addons": [entry]}}) == [expected]


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"id": "data", "optional": "yes"}, "optional must be true or false"),
        ({"id": "data", "soft": True}, "unknown field soft"),
        ({"id": "data", "name": "data"}, "not both"),
        ({"id": "Data Module"}, "must be a name"),
        ("", "must be a name"),
    ],
)
def test_a_malformed_requirement_is_refused(entry, message):
    with pytest.raises(ValueError, match=message):
        compat.addon_requirements({"requires": {"addons": [entry]}})


def _setup(repo_root: Path, config_dir: Path) -> None:
    from lib import envtree

    envtree.init(config_dir, repo_root, env_name="papaia")


def _plain_addon(tmp_path: Path, name: str, requires: list | None = None) -> Path:
    path = tmp_path / f"addon-{name}"
    path.mkdir()
    manifest: dict = {"name": name, "version": "0.1.0", "papaia_compat": ">=0.8.0"}
    if requires is not None:
        manifest["requires"] = {"addons": requires}
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return path


def _args(config_dir: Path, repo_root: Path, name: str, path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(repo_root), name=name, path=str(path),
        version=None, force=False,
    )


def test_an_optional_dependency_that_is_missing_keeps_the_install_green(
    repo_root, config_dir, tmp_path, capsys
):
    _setup(repo_root, config_dir)
    studio = _plain_addon(tmp_path, "papaia-studio", [{"id": "papaia-data", "optional": True}])

    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "papaia-studio", studio)) == 0
    err = _err(capsys)
    assert "optional add-on 'papaia-data' is not installed and active" in err
    assert "ERROR" not in err


def test_a_required_dependency_that_is_missing_still_refuses(
    repo_root, config_dir, tmp_path, capsys
):
    _setup(repo_root, config_dir)
    studio = _plain_addon(tmp_path, "papaia-studio", [{"id": "papaia-data"}])

    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "papaia-studio", studio)) == 2
    assert "'papaia-data' is not installed and active" in _err(capsys)


def test_an_optional_user_does_not_block_removing_what_it_uses(
    repo_root, config_dir, tmp_path, capsys
):
    _setup(repo_root, config_dir)
    data = _plain_addon(tmp_path, "papaia-data")
    studio = _plain_addon(tmp_path, "papaia-studio", [{"id": "papaia-data", "optional": True}])
    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "papaia-data", data)) == 0
    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "papaia-studio", studio)) == 0
    capsys.readouterr()
    args = argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(repo_root), name="papaia-data", force=False
    )

    assert cli_addon.cmd_addon_dependents(args) == 0
    assert "'papaia-studio' uses 'papaia-data' optionally" in _err(capsys)


def test_active_addons_lists_data_before_studio(repo_root, config_dir, tmp_path, capsys):
    """The order `start` and `upgrade` bring add-ons up in (RE-42)."""
    _setup(repo_root, config_dir)
    studio = _plain_addon(tmp_path, "papaia-studio", [{"id": "papaia-data", "optional": True}])
    data = _plain_addon(tmp_path, "papaia-data")
    flow = _plain_addon(tmp_path, "papaia-flow")
    for name, path in (("papaia-studio", studio), ("papaia-flow", flow), ("papaia-data", data)):
        assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, name, path)) == 0
    capsys.readouterr()

    args = argparse.Namespace(config_dir=str(config_dir), repo_root=str(repo_root))
    assert cli_addon.cmd_active_addons(args) == 0
    assert capsys.readouterr().out.split() == ["papaia-flow", "papaia-data", "papaia-studio"]


def test_the_dependency_order_keeps_a_cycle_in_the_given_order():
    manifests = {
        "a": {"requires": {"addons": ["b"]}},
        "b": {"requires": {"addons": ["a"]}},
        "c": {"requires": {"addons": "not-a-list"}},
    }
    assert compat.dependency_order(["a", "b", "c"], manifests) == ["c", "a", "b"]


# ─────────────────────────────────────────────────────────────────────────
# Paperless only with its gate (BE-03 Nr. 6, E-38)
# ─────────────────────────────────────────────────────────────────────────


def _paperless(tmp_path: Path, *, gate: bool) -> Path:
    path = tmp_path / ("paperless-gated" if gate else "paperless-plain") / "paperless"
    shutil.copytree(ADDON_PAPERLESS, path)
    services: dict = {"paperless": {"image": "example.invalid/paperless:2.0.0"}}
    if gate:
        services["paperless-gate"] = {
            "image": "example.invalid/gate:1.0.0", "network_mode": "service:paperless"
        }
    (path / "docker-compose.yml").write_text(yaml.safe_dump({"services": services}))
    return path


def test_paperless_without_its_gate_is_not_installed(repo_root, config_dir, tmp_path, capsys):
    _setup(repo_root, config_dir)
    before = (config_dir / "deployment.yaml").read_bytes()
    plain = _paperless(tmp_path, gate=False)

    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", plain)) == 2
    assert "brings no gate" in _err(capsys)
    assert (config_dir / "deployment.yaml").read_bytes() == before


def test_paperless_with_its_gate_is_installed(repo_root, config_dir, tmp_path):
    _setup(repo_root, config_dir)
    gated = _paperless(tmp_path, gate=True)
    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", gated)) == 0


# ─────────────────────────────────────────────────────────────────────────
# addon uninstall: what the realm and the proxy still have to remove
# ─────────────────────────────────────────────────────────────────────────


def _uninstall_args(config_dir: Path, repo_root: Path, name: str, *, purge: bool = False):
    return argparse.Namespace(
        config_dir=str(config_dir), repo_root=str(repo_root), name=name, purge_data=purge
    )


def test_uninstall_records_clients_and_proxy_hosts_and_audits(repo_root, config_dir, tmp_path):
    _setup(repo_root, config_dir)
    gated = _paperless(tmp_path, gate=True)
    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", gated)) == 0
    _write_env(
        config_dir / "addons" / "paperless" / ".env",
        {"PAPERLESS_PUBLIC_URL": "https://paperless.papaia.example"},
    )

    assert cli_addon.cmd_addon_uninstall(
        _uninstall_args(config_dir, repo_root, "paperless", purge=True)
    ) == 0

    assert uninstall_journal.load(config_dir) == {
        "paperless": {"pending": ["proxy", "realm"], "proxy_hosts": ["paperless.papaia.example"]}
    }
    assert uninstall_journal.path(config_dir).stat().st_mode & 0o777 == 0o600
    rows = [json.loads(line) for line in rs.audit_path(config_dir).read_text().splitlines()]
    row = next(r for r in rows if r["operation"] == "addon.uninstall")
    assert row["effect"] == "delete"
    assert row["object_ref"] == {"type": "addon", "id": "paperless"}
    assert row["writer"] == "papaia-ctl/addon"
    assert row["correlation_id"]

    # Installed again: nothing of it is removed any more.
    assert cli_addon.cmd_addon_install(_args(config_dir, repo_root, "paperless", gated)) == 0
    assert uninstall_journal.load(config_dir) == {}


def test_the_realm_sync_deletes_the_clients_of_an_uninstalled_module():
    realm = FakeRealm()
    rs.reconcile(realm.call, _full_plan(), apply=True)
    assert realm.by_client_id("flow-engine")
    plan = _plan([_studio(), _paperless_module()])
    plan.uninstalled = frozenset({"flow"})

    changes = rs.reconcile(realm.call, plan, apply=True)

    deleted = {c.name for c in changes if c.operation == "delete_client"}
    assert "flow-engine" in deleted
    with pytest.raises(StopIteration):
        realm.by_client_id("flow-engine")
    assert realm.by_client_id("papaia-studio-gateway")
    assert rs.reconcile(realm.call, plan, apply=True) == []


def test_sync_reads_the_journal_and_clears_its_part(tmp_path, monkeypatch, capsys):
    from tests.test_realm_sync import _tree

    realm = FakeRealm()
    rs.reconcile(realm.call, _plan([_flow(delegation=DELEGATION)]), apply=True)

    def sign_in(base_url, ctx, secret):
        client = next((c for c in realm.clients.values() if c["clientId"] == rs.SYNC_CLIENT), None)
        if client is None or client.get("secret") != secret:
            raise rs.urllib.error.HTTPError("u", 401, "unauthorized", {}, None)
        return "sync-token"

    monkeypatch.setattr(rs.kcs, "_wait_for_keycloak", lambda *a, **k: None)
    monkeypatch.setattr(rs.kcs, "_get_admin_token", lambda *a: "master-token")
    monkeypatch.setattr(rs, "_client_credentials", sign_in)
    monkeypatch.setattr(rs.AdminApi, "call", lambda self, *a: realm.call(*a))
    config_dir, repo_root = tmp_path / "config", tmp_path / "repo"
    config_dir.mkdir()
    repo_root.mkdir()
    (config_dir / "deployment.yaml").write_text(yaml.safe_dump({"addons": []}))
    uninstall_journal.record(config_dir, "papaia-flow", [])

    assert rs.sync(_tree(), config_dir, repo_root) == 0
    with pytest.raises(StopIteration):
        realm.by_client_id("flow-engine")
    assert uninstall_journal.load(config_dir) == {}
    rows = [json.loads(line) for line in rs.audit_path(config_dir).read_text().splitlines()]
    assert any(
        r["operation"] == "realm_sync.delete_client" and r["object_ref"]["id"] == "flow-engine"
        for r in rows
    )


def test_npm_provision_deletes_only_the_recorded_hosts_nobody_serves(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    uninstall_journal.record(
        config_dir, "paperless", ["paperless.papaia.example", "shared.papaia.example"]
    )
    hosts = [
        {"id": 1, "domain_names": ["paperless.papaia.example"]},
        {"id": 2, "domain_names": ["shared.papaia.example"]},
        {"id": 3, "domain_names": ["chat.papaia.example"]},
    ]
    calls: list[tuple[str, str]] = []

    def send(base_url, token, path, method, body=None):
        calls.append((method, path))
        return hosts if method == "GET" else None

    monkeypatch.setattr(npm_provision, "_send", send)

    assert npm_provision._uninstalled_hosts(
        "http://npm", "token", config_dir, {"shared.papaia.example", "chat.papaia.example"}
    )
    assert [c for c in calls if c[0] == "DELETE"] == [("DELETE", "/api/nginx/proxy-hosts/1")]
    assert uninstall_journal.load(config_dir) == {
        "paperless": {
            "pending": ["realm"],
            "proxy_hosts": ["paperless.papaia.example", "shared.papaia.example"],
        }
    }
    rows = [json.loads(line) for line in rs.audit_path(config_dir).read_text().splitlines()]
    assert [(r["operation"], r["object_ref"]["id"], r["effect"]) for r in rows] == [
        ("npm_provision.delete_proxy_host", "paperless.papaia.example", "delete")
    ]


@pytest.mark.parametrize(
    "doc",
    [
        {"format": "other", "modules": {}},
        {"format": uninstall_journal.FORMAT, "modules": {"Bad Name": {}}},
        {
            "format": uninstall_journal.FORMAT,
            "modules": {"x": {"pending": ["realm"], "proxy_hosts": ["a b"]}},
        },
        {
            "format": uninstall_journal.FORMAT,
            "modules": {"x": {"pending": ["realm"], "proxy_hosts": [], "extra": 1}},
        },
    ],
)
def test_a_journal_that_does_not_pass_is_refused(tmp_path, doc):
    file = uninstall_journal.path(tmp_path)
    file.parent.mkdir(parents=True)
    file.write_text(json.dumps(doc))
    with pytest.raises(uninstall_journal.JournalError):
        uninstall_journal.load(tmp_path)


def test_root_env_is_not_needed_for_the_journal(tmp_path):
    """The journal carries names only: nothing of the root .env reaches it."""
    _write_env(tmp_path / ".env", ROOT_ENV)
    uninstall_journal.record(tmp_path, "probe", [])
    text = uninstall_journal.path(tmp_path).read_text()
    assert all(value not in text for value in ROOT_ENV.values())
