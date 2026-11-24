"""The core profile `connections`: the connection registry (ADR 0021).

Three services of one module (`de.fidonis.module: papaia-connections`): the registry,
the one-shot `connections-migrate` that holds the owner login of the schema, and the
database. The tests read the real checkout (compose file, request files, catalog
declaration) and run `setup` against a copy of it, so the profile on and off can be
compared: on, the realm plan holds the role `connections-admin` and the bearer client
`papaia-connections`, the platform PKI issues the registry's certificate and the catalog
lists the registry; off, none of them exists.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from lib import (
    audit,
    backup,
    catalog,
    cli,
    common,
    compat,
    connections_profile,
    defaults,
    envtree,
    exposes,
    me_profile,
    modules,
    pki,
    resolve,
    suite,
    topology,
)
from lib import realm_sync as rs

REPO = Path(__file__).resolve().parents[2]
PROFILE_DIR = REPO / "src" / "infra" / "connections"
COMPOSE = PROFILE_DIR / "docker-compose.yml"
SERVICES = {"connections", "connections-migrate", "connections-db"}
CONSUMER_NET = "papaia-connections-net"
DB_NET = "papaia-connections-db-net"


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _core_services() -> dict[str, dict]:
    """Every service of every core compose file, by name."""
    found: dict[str, dict] = {}
    for path in compat.compose_files(REPO / "src" / "docker-compose.yml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        found.update({name: body or {} for name, body in (doc.get("services") or {}).items()})
    return found


def _networks(service: dict) -> set[str]:
    networks = service.get("networks") or []
    return set(networks if isinstance(networks, list) else networks.keys())


# ── the compose file ─────────────────────────────────────────────────────────


def test_the_root_compose_includes_the_profile():
    root = yaml.safe_load((REPO / "src" / "docker-compose.yml").read_text(encoding="utf-8"))
    assert {"path": "./infra/connections/docker-compose.yml"} in root["include"]


def test_three_services_of_one_module_on_the_profile_with_pinned_images():
    services = _compose()["services"]
    assert set(services) == SERVICES
    for name, body in services.items():
        assert body["profiles"] == ["connections"], name
        assert body["labels"]["de.fidonis.module"] == "papaia-connections", name
        assert me_profile.PINNED_IMAGE_RE.fullmatch(body["image"]), name
        assert not body.get("ports") and body.get("network_mode") != "host", name
    assert services["connections"]["image"] == services["connections-migrate"]["image"]
    assert services["connections"]["image"].startswith("ghcr.io/fidonis/papaia-connections:")


def test_the_registry_never_sees_the_owner_login():
    services = _compose()["services"]
    registry = services["connections"]["environment"]
    migrate = services["connections-migrate"]["environment"]
    assert "CONNECTIONS_MIGRATE_DB_URL" not in registry
    assert "CONNECTIONS_DEV_OWNER_LOGIN" not in registry
    assert registry["CONNECTIONS_DB_URL"].startswith("postgresql://connections_service:")
    assert migrate["CONNECTIONS_MIGRATE_DB_URL"].startswith("postgresql://connections_owner:")
    # The init container reads only the login name of the service's URL.
    assert migrate["CONNECTIONS_DB_URL"] == "postgresql://connections_service@connections-db:5432/connections"
    assert services["connections-migrate"]["command"] == ["migrate"]
    assert services["connections-migrate"]["restart"] == "no"
    assert services["connections"]["depends_on"]["connections-migrate"] == {
        "condition": "service_completed_successfully"
    }
    db = services["connections-db"]["environment"]
    assert db["POSTGRES_USER"] == "connections_owner"
    assert "POSTGRES_PASSWORD" not in db  # from a file, never a variable of the container


def test_both_logins_have_their_own_generated_password():
    example = common.parse_env_file(PROFILE_DIR / ".env.example")
    assert example["CONNECTIONS_OWNER_DB_PASSWORD"] == "GENERATE_CONNECTIONS_OWNER_DB_PASSWORD"
    assert example["CONNECTIONS_SERVICE_DB_PASSWORD"] == "GENERATE_CONNECTIONS_SERVICE_DB_PASSWORD"


def test_the_registry_and_the_init_container_run_locked_down():
    services = _compose()["services"]
    for name in ("connections", "connections-migrate"):
        body = services[name]
        assert body["read_only"] is True, name
        assert body["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in body["security_opt"], name
        assert str(body["user"]) == "10001:10001", name


def test_the_registry_network_reaches_only_the_declared_consumers():
    members = {name for name, body in _core_services().items() if CONSUMER_NET in _networks(body)}
    # me-web joins only through the override of both profiles (tests/test_me_connections.py).
    assert members == {"connections"}
    registry = _compose()["services"]["connections"]
    assert "papaia-net" not in _networks(registry)
    assert _networks(registry) == {CONSUMER_NET, DB_NET, "papaia-audit-ingest-net"}


def test_the_database_is_reachable_by_the_registry_and_the_init_container_only():
    members = {name for name, body in _core_services().items() if DB_NET in _networks(body)}
    assert members == SERVICES
    assert _compose()["networks"][DB_NET]["internal"] is True
    assert _networks(_compose()["services"]["connections-db"]) == {DB_NET}
    assert _networks(_compose()["services"]["connections-migrate"]) == {DB_NET}


def test_the_key_volume_is_mounted_by_the_registry_alone():
    mounting = {
        name
        for name, body in _core_services().items()
        for entry in body.get("volumes") or []
        if isinstance(entry, str) and entry.split(":", 1)[0] == "connections-keys"
    }
    assert mounting == {"connections"}
    assert set(_compose()["volumes"]) == {"connections-db", "connections-keys"}


def test_add_ons_may_attach_the_registry_but_never_its_database():
    assert "connections-db" in compat.NEVER_ATTACHABLE
    assert "connections-migrate" in compat.NEVER_ATTACHABLE
    assert "connections" not in compat.NEVER_ATTACHABLE


def test_the_registry_serves_mutual_tls_with_the_platform_pki():
    registry = _compose()["services"]["connections"]
    env = registry["environment"]
    assert env["CONNECTIONS_TLS_CERT"] == "/run/papaia/tls/tls.crt"
    assert env["CONNECTIONS_TLS_KEY"] == "/run/papaia/tls/tls.key"
    assert env["CONNECTIONS_TLS_CLIENT_CA"] == "${CONNECTIONS_TLS_CLIENT_CA-/run/papaia/tls/ca.crt}"
    assert "${PAPAIA_CONFIG_DIR}/pki/core/connections:/run/papaia/tls:ro" in registry["volumes"]
    requests = pki.core_requests(REPO, {"connections"})
    ours = [(r.module, r.name, r.uid, r.dns, r.client) for r in requests if r.name == "connections"]
    assert ours == [("core", "connections", 10001, ("connections",), False)]
    assert not [r for r in pki.core_requests(REPO, set()) if r.name == "connections"]


def test_the_audit_rows_reach_papaia_audit_with_a_source_certificate():
    assert "papaia-connections" in audit.SOURCES
    registry = _compose()["services"]["connections"]
    assert registry["environment"]["CONNECTIONS_AUDIT_URL"] == "https://papaia-audit:8443/v1/ingest"
    assert (
        "${PAPAIA_CONFIG_DIR}/infra/audit/clients/papaia-connections:/run/papaia/audit:ro"
        in registry["volumes"]
    )


def test_the_env_example_documents_exactly_the_own_interpolated_variables():
    root = set(common.parse_env_file(REPO / "src" / ".env.example"))
    own = me_profile.interpolated(COMPOSE) - root
    documented = set(common.parse_env_file(PROFILE_DIR / ".env.example"))
    assert own - documented == set()
    assert documented - own == set()


# ── catalog, suite, contract ─────────────────────────────────────────────────


def test_the_catalog_lists_the_registry_only_while_the_profile_is_on():
    assert catalog.CORE_PROFILES["connections"] == "src/infra/connections"
    on = catalog._core_sources(REPO, {"COMPOSE_PROFILES": "keycloak,connections"}, "1.10.0")
    assert [s.provider for s in on] == ["core:connections"]
    assert [e["id"] for e in on[0].section] == ["connections"]
    assert on[0].section[0]["audience"] == "papaia-connections"
    address = {"service": "connections", "port": 8080, "scheme": "https"}
    assert on[0].section[0]["address"] == address
    exposes.check(on[0].section, on[0].provider)  # the declaration is valid exposes.v1
    assert catalog._core_sources(REPO, {"COMPOSE_PROFILES": "keycloak"}, "1.10.0") == []


def test_the_suite_lists_the_registry():
    matrix = yaml.safe_load((REPO / "compat" / "suite.yaml").read_text(encoding="utf-8"))
    assert "papaia-connections" in matrix["components"]
    candidate = next(row for row in matrix["suites"] if row["suite"] == "1.10.0")
    assert candidate["versions"]["papaia-connections"] == ">=0.1.0,<0.2.0"
    suite.load_matrix(REPO)  # still a valid matrix


def test_adr_0021_is_written_and_no_longer_reserved():
    adr_dir = REPO / "docs" / "adr"
    assert len(list(adr_dir.glob("0021-*.md"))) == 1
    readme = (adr_dir / "README.md").read_text(encoding="utf-8")
    reserved = readme.split("## Reserved numbers", 1)[1].split("\n## ", 1)[0]
    assert "| 0021 |" not in reserved
    assert "[0021](./0021-" in readme.split("## Reserved numbers", 1)[0]


# ── setup: the profile on and off ────────────────────────────────────────────


@pytest.fixture
def real_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(
        REPO / "src",
        root / "src",
        ignore=shutil.ignore_patterns(".env", "node_modules", "__pycache__", "tests"),
    )
    (root / "tools").mkdir()
    shutil.copy(REPO / "tools" / "deployment.template.yaml", root / "tools")
    for name in ("VERSION", "ADDON_API"):
        shutil.copy(REPO / name, root / name)
    return root


def _setup(repo_root: Path, config_dir: Path, *flags: str) -> int:
    return cli.main(
        [
            "--repo-root",
            str(repo_root),
            "--config-dir",
            str(config_dir),
            "setup",
            "--app-host=https://papaia.example.com",
            *flags,
        ]
    )


def _profiles(config_dir: Path) -> list[str]:
    return common.parse_env_file(config_dir / ".env")["COMPOSE_PROFILES"].split(",")


def _toggle(repo_root: Path, profiles: str, choice: bool | None) -> str:
    tree = envtree.load_seed_tree(repo_root)
    tree[""]["COMPOSE_PROFILES"] = profiles
    args = resolve.SetupArgs(config_dir=repo_root, non_interactive=True, enable_connections=choice)
    return resolve.resolve_connections(tree, args)[""]["COMPOSE_PROFILES"]


def test_toggle_adds_and_removes_only_the_profile(repo_root):
    assert _toggle(repo_root, "keycloak,librechat", True) == "keycloak,librechat,connections"
    assert _toggle(repo_root, "keycloak,librechat,connections", True) == (
        "keycloak,librechat,connections"
    )
    assert _toggle(repo_root, "keycloak,connections,librechat", False) == "keycloak,librechat"
    for profiles in ("keycloak,librechat", "keycloak,connections,librechat"):
        assert _toggle(repo_root, profiles, None) == profiles


def _realm_plan(config_dir: Path, repo_root: Path) -> rs.Plan:
    return rs.build_plan(rs.load_register(), rs.load_modules(config_dir, repo_root), [])


def test_profile_off_creates_no_role_client_or_certificate(real_repo, config_dir):
    assert _setup(real_repo, config_dir) == 0

    assert "connections" not in _profiles(config_dir)
    plan = _realm_plan(config_dir, real_repo)
    assert "connections-admin" not in plan.roles
    assert "papaia-connections" not in plan.clients
    assert [r.name for r in pki.collect(config_dir, real_repo) if r.name == "connections"] == []
    env = common.parse_env_file(config_dir / "platform" / ".." / ".env")
    assert "connections" not in catalog._profiles(env)


def test_profile_on_creates_the_role_the_client_and_the_certificate_request(real_repo, config_dir):
    assert _setup(real_repo, config_dir, "--enable-connections=true") == 0

    assert "connections" in _profiles(config_dir)
    plan = _realm_plan(config_dir, real_repo)
    assert plan.roles["connections-admin"] == "papaia-connections"
    assert "connections-admin" in plan.admin_members
    client = plan.clients["papaia-connections"]
    assert (client.kind, client.owner, client.token_exchange) == (
        "bearer",
        "papaia-connections",
        False,
    )
    issued = pki.collect(config_dir, real_repo)
    assert [(r.module, r.name) for r in issued if r.name == "connections"] == [
        ("core", "connections")
    ]
    stored = common.parse_env_file(config_dir / "infra" / "connections" / ".env")
    owner = stored["CONNECTIONS_OWNER_DB_PASSWORD"]
    service = stored["CONNECTIONS_SERVICE_DB_PASSWORD"]
    assert len(owner) >= 32 and len(service) >= 32 and owner != service
    assert not owner.startswith("GENERATE_") and not service.startswith("GENERATE_")

    # A second run without the flag keeps the profile and both passwords.
    assert _setup(real_repo, config_dir) == 0
    again = common.parse_env_file(config_dir / "infra" / "connections" / ".env")
    assert "connections" in _profiles(config_dir)
    assert again["CONNECTIONS_OWNER_DB_PASSWORD"] == owner
    assert again["CONNECTIONS_SERVICE_DB_PASSWORD"] == service
    assert defaults.compute_defaults(config_dir, real_repo)["CONNECTIONS_STICKY"] == "true"


def test_the_core_registry_module_is_refused_when_its_declaration_names_a_foreign_role(
    real_repo, config_dir
):
    assert _setup(real_repo, config_dir, "--enable-connections=true") == 0
    declaration = real_repo / "src" / "infra" / "connections" / "exposes.yaml"
    doc = yaml.safe_load(declaration.read_text(encoding="utf-8"))
    doc["exposes"][0]["roles"] = [{"name": "flow-admin"}]
    declaration.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(rs.RealmSyncError, match="flow-admin belongs to papaia-flow"):
        _realm_plan(config_dir, real_repo)


def test_the_role_is_registered_by_the_core_until_the_kit_lists_it():
    snapshot = json.loads(rs.REGISTER_PATH.read_text(encoding="utf-8"))
    kit_roles = {e["name"] for e in snapshot["entries"] if e["kind"] == "role"}
    pending = {e["name"] for e in rs.PROFILE_ENTRIES}
    # Once the kit's register carries a name, its entry here must go.
    assert pending.isdisjoint(kit_roles)
    register = rs.load_register()
    assert register.roles["connections-admin"].owner == "papaia-connections"


def test_the_module_owns_its_settings_and_its_data_together():
    spec = modules.MODULES["connections"]
    assert spec.profile == "connections"
    assert spec.env_dirs == ("infra/connections",)
    assert spec.settings_need_data is True


def test_the_registry_is_one_service_of_the_topology():
    spec = topology.CATALOGUE["connections"]
    assert spec.profiles == ("connections",)
    assert spec.env_dirs == ("infra/connections",)
    assert "connections" in topology.CONTROLLER_ONLY


# ── backup and restore ───────────────────────────────────────────────────────


def test_both_volumes_are_backed_up_encrypted_as_one_module(real_repo, config_dir, tmp_path):
    assert _setup(real_repo, config_dir, "--enable-connections=true") == 0
    project = common.parse_env_file(config_dir / ".env").get("COMPOSE_PROJECT_NAME") or "papaia"
    existing = [(project, f"{project}_{key}") for key in backup.resolve_core_volumes(real_repo)]
    plan = backup.build_plan(
        config_dir, real_repo, tmp_path / "backup", existing=existing, now=datetime(2026, 11, 1)
    )
    ours = [a for a in plan.artifacts if a.module == "connections"]
    assert sorted(a.source for a in ours) == [
        f"{project}_connections-db",
        f"{project}_connections-keys",
    ]
    assert all(a.archive.endswith(backup.ARCHIVE_SUFFIX) for a in ours)
    assert all(a.profiles == ["connections"] for a in ours)
    assert not [e for e in plan.excluded if "connections" in e["volume"]]

    scoped = backup.scope_plan(plan, "module:connections")
    assert sorted(a.source for a in scoped.artifacts if a.kind == "volume") == sorted(
        a.source for a in ours
    )

    # A restore of the module takes both archives, and only these, back.
    common.ensure_dir(plan.snapshot)
    manifest = backup.write_manifest(
        plan.snapshot, plan, {a.archive: "ok" for a in plan.artifacts}, papaia_version="1.10.0"
    )
    selection = backup.resolve_selection(manifest, "module:connections")
    assert sorted(a.source for a in selection.artifacts) == sorted(a.source for a in ours)
    assert selection.profiles == ["connections"]


# ── secrets rotate connections/credentials ───────────────────────────────────


class _Docker:
    """`docker ps` and `docker exec` as the running registry answers them."""

    def __init__(self, running: bool = True, exec_rc: int = 0):
        self.calls: list[list[str]] = []
        self.running, self.exec_rc = running, exec_rc

    def __call__(self, args, **kwargs):
        import subprocess

        self.calls.append(list(args))
        if args[:2] == ["docker", "ps"]:
            out = "abc123\n" if self.running else ""
            return subprocess.CompletedProcess(args, 0, out, "")
        if args[:2] == ["docker", "exec"]:
            out = "2 credentials re-encrypted under k-2\n"
            if self.exec_rc != 0:
                out = "keys not changed: CONNECTIONS-KEYS\n"
            return subprocess.CompletedProcess(args, self.exec_rc, out, "")
        raise AssertionError(args)


def _audit_rows(config_dir: Path) -> list[dict]:
    path = config_dir / "audit" / "papaia-ctl.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _seed(config_dir: Path, profiles: str = "keycloak,connections") -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / ".env").write_text(
        f"COMPOSE_PROJECT_NAME=papaia\nCOMPOSE_PROFILES={profiles}\n", encoding="utf-8"
    )


def test_rotation_reseals_every_credential_in_the_running_registry(config_dir):
    _seed(config_dir)
    docker = _Docker()
    correlation = "0b6b9b5e-4c4f-4f43-9f0e-2f0c6f1b2a10"

    summary = connections_profile.rotate_credentials(
        config_dir, correlation=correlation, run=docker
    )

    assert summary == "2 credentials re-encrypted under k-2"
    ps, exec_ = docker.calls
    assert "label=com.docker.compose.project=papaia" in ps
    assert "label=com.docker.compose.service=connections" in ps
    assert exec_ == ["docker", "exec", "abc123", "/app/.venv/bin/python", "-m",
                     "papaia_connections.main", "rotate-keys"]  # fmt: skip
    (row,) = _audit_rows(config_dir)
    assert (row["format"], row["operation"], row["event"], row["effect"], row["result"]) == (
        "papaia.audit/1",
        "secrets-rotate",
        "connections_credentials_rotated",
        "write",
        "allowed",
    )
    assert row["correlation_id"] == correlation
    assert row["detail"] == {"target": "connections/credentials"}


def test_a_failed_rotation_is_refused_and_recorded(config_dir):
    _seed(config_dir)
    with pytest.raises(connections_profile.ConnectionsError, match="rotate-keys failed"):
        connections_profile.rotate_credentials(config_dir, run=_Docker(exec_rc=1))
    (row,) = _audit_rows(config_dir)
    assert (row["result"], row["error_code"]) == ("failed", "rotate_keys_failed")


@pytest.mark.parametrize(
    ("profiles", "running", "message"),
    [
        ("keycloak", True, "profile connections is not on"),
        ("keycloak,connections", False, "the registry is not running"),
    ],
)
def test_rotation_needs_the_running_registry(config_dir, profiles, running, message):
    _seed(config_dir, profiles)
    docker = _Docker(running=running)
    with pytest.raises(connections_profile.ConnectionsError, match=message):
        connections_profile.rotate_credentials(config_dir, run=docker)
    assert not [c for c in docker.calls if c[:2] == ["docker", "exec"]]
    assert not (config_dir / "audit" / "papaia-ctl.jsonl").exists()


def test_the_rotation_targets_are_listed_and_checked(config_dir, capsys):
    _seed(config_dir)
    assert "connections/credentials" in connections_profile.ROTATE_TARGETS
    code = cli.main(
        ["--repo-root", str(REPO), "--config-dir", str(config_dir), "secrets-rotate",
         "--target", "connections/everything"]
    )  # fmt: skip
    assert code == 2
    assert "connections/credentials" in capsys.readouterr().err
