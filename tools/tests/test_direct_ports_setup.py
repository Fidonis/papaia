"""`setup` and the edge-only ports: the direct-ports override, the refusal for protected
services, and the internal path of the Keycloak admin steps.

- `setup --allow-direct-port-access` (or `no_proxy`) writes the direct-ports override only
  when no installed service has header identity, is `me-web` or belongs to a module with
  `delegation`; otherwise it refuses and writes nothing.
- The local default installation is served on the edge: Keycloak, the forward-auth
  proxy and the NPM admin UI on `.localhost` names with the edge port, no Keycloak port.
- The Keycloak admin steps run on the stack network in a one-shot container, never
  through the edge and never through a host port.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from install_helpers import Installation

from lib import cli, common, deployment, direct_ports, ingress, keycloak_admin_path, resolve

EDGE = "57143"


def _addon(root: Path, name: str, services: dict, exposes: list | None = None) -> dict:
    path = root / "addons" / name
    path.mkdir(parents=True)
    manifest: dict = {"name": name, "version": "1.0.0"}
    if exposes is not None:
        manifest["exposes"] = exposes
    (path / "papaia-app.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (path / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": services}), encoding="utf-8"
    )
    return {"name": name, "path": str(path), "active": True}


def _setup(inst: Installation, *flags: str) -> int:
    return cli.main(
        ["--repo-root", str(inst.repo), "--config-dir", str(inst.config), "setup", "--env=itest",
         "--app-host=http://host.docker.internal", *flags]
    )


def _with_addon(tmp_path: Path, inst: Installation, addon: dict) -> None:
    manifest = deployment.load(inst.config)
    manifest["addons"] = [addon]
    deployment.save(inst.config, manifest)


PROTECTED = {
    "header identity": lambda root: _addon(
        root, "paperless", {"paperless": {"image": "x"}},
        [{"id": "paperless.web", "kind": "ui", "identity": ["person"], "header_identity": True,
          "address": {"service": "paperless", "port": 8000, "scheme": "http"}}],
    ),
    "me-web": lambda root: _addon(root, "me", {"me-web": {"image": "x"}}),
    "delegation": lambda root: _addon(
        root, "flow", {"flow-api": {"image": "x"}},
        [{"id": "flow.api", "kind": "rest", "identity": ["person"],
          "delegation": {"purposes": ["flow.run"]},
          "address": {"service": "flow-api", "port": 8000, "scheme": "http"}}],
    ),
}


@pytest.mark.parametrize("kind", sorted(PROTECTED))
@pytest.mark.parametrize(
    "flag", ["--allow-direct-port-access", "--reverse-proxy-provider=no_proxy"]
)
def test_setup_refuses_direct_port_access_for_a_protected_service(tmp_path, capsys, kind, flag):
    inst = Installation(tmp_path, [])
    assert _setup(inst) == 0
    _with_addon(tmp_path, inst, PROTECTED[kind](tmp_path))
    capsys.readouterr()
    assert _setup(inst, flag) == cli.SETUP_REFUSED
    err = capsys.readouterr().err
    assert "direct port access" in err and kind in err
    assert not (inst.config / direct_ports.OVERRIDE).exists()


@pytest.mark.parametrize(
    "flag", ["--allow-direct-port-access", "--reverse-proxy-provider=no_proxy"]
)
def test_setup_writes_the_override_without_a_protected_service(tmp_path, flag):
    inst = Installation(tmp_path, [])
    assert _setup(inst, flag) == 0
    text = (inst.config / direct_ports.OVERRIDE).read_text(encoding="utf-8")
    assert "KEYCLOAK_EXT_PORT" in text
    root = common.parse_env_file(inst.config / ".env")
    assert direct_ports.verify(inst.config, root) == []


def test_setup_behind_the_edge_removes_an_earlier_override(tmp_path):
    inst = Installation(tmp_path, [])
    assert _setup(inst, "--allow-direct-port-access") == 0
    assert (inst.config / direct_ports.OVERRIDE).exists()
    assert _setup(inst) == 0
    assert not (inst.config / direct_ports.OVERRIDE).exists()


# ─────────────────────────────────────────────────────────────────────────
# the local default installation on the edge
# ─────────────────────────────────────────────────────────────────────────


def _resolved(repo_root, **kwargs):
    from lib import envtree

    tree = envtree.load_seed_tree(repo_root)
    tree[""]["INGRESS_HTTPS_EXT_PORT"] = EDGE
    args = resolve.SetupArgs(
        config_dir=repo_root,
        env_name="itest",
        app_host=kwargs.pop("app_host", "http://host.docker.internal"),
        non_interactive=True,
        fresh_init=kwargs.pop("fresh", True),
        **kwargs,
    )
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_hostnames(tree, args)
    return resolve.resolve_reverse_proxy(tree, args)


def test_the_local_default_install_signs_in_through_the_edge(repo_root):
    tree = _resolved(repo_root)
    root = tree[""]
    assert root["AUTH_HOST"] == f"https://auth.itest.papaia.localhost:{EDGE}"
    assert root["OAUTH2_PROXY_PUBLIC_URL"] == f"https://oauth2.itest.papaia.localhost:{EDGE}"
    assert root["NPM_ADMIN_HOST"] == f"https://npm.itest.papaia.localhost:{EDGE}"
    assert root["LITELLM_PUBLIC_URL"] == f"https://litellm.itest.papaia.localhost:{EDGE}"
    assert direct_ports.direct_mode(root) is None
    assert not keycloak_admin_path.keycloak_published(root)


def test_the_edge_serves_the_forward_auth_proxy_and_the_npm_admin_ui(repo_root):
    tree = _resolved(repo_root)
    found = {r.host_key: r for r in ingress.core_routes(tree)}
    assert found["oauth2"].target == "http://oauth2-proxy:4180"
    assert found["npm"].target == "http://nginx-proxy-manager-auth:4180"
    assert found["auth"].target == "https://keycloak:8443"
    # The admin API of the identity provider is never routed through the edge: the
    # proxy host for Keycloak exists, its admin paths are blocked (npm_provision).
    assert "nginx-proxy-manager:81" not in {r.target for r in found.values()}


def test_an_earlier_port_address_moves_onto_the_edge(repo_root):
    # Stored by an earlier release that derived ports: no port is published any more.
    from lib import envtree

    tree = envtree.load_seed_tree(repo_root)
    tree[""].update(
        {
            "PAPAIA_HOST": "http://host.docker.internal",
            "COMPOSE_PROJECT_NAME": "papaia-itest",
            "INGRESS_HTTPS_EXT_PORT": EDGE,
            "REVERSE_PROXY_PROVIDER": "internal_nginx",
            "MANAGER_PUBLIC_URL": "http://host.docker.internal:8120",
            "LITELLM_PUBLIC_URL": "http://host.docker.internal:8200",
            "NPM_ADMIN_HOST": "http://localhost:8100",
        }
    )
    tree["ai/librechat"]["DOMAIN_SERVER"] = "http://localhost:8000"
    args = resolve.SetupArgs(
        config_dir=repo_root, env_name="itest", non_interactive=True, fresh_init=False
    )
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["MANAGER_PUBLIC_URL"] == f"https://manager.itest.papaia.localhost:{EDGE}"
    assert tree[""]["LITELLM_PUBLIC_URL"] == f"https://litellm.itest.papaia.localhost:{EDGE}"
    assert tree[""]["NPM_ADMIN_HOST"] == f"https://npm.itest.papaia.localhost:{EDGE}"
    assert tree["ai/librechat"]["DOMAIN_SERVER"] == f"https://chat.itest.papaia.localhost:{EDGE}"


def test_a_lan_address_behind_the_bundled_proxy_needs_a_domain(repo_root):
    with pytest.raises(resolve.SetupError, match="INGRESS_DOMAIN"):
        _resolved(repo_root, app_host="http://192.168.50.20")


def test_a_lan_address_with_a_domain_gets_host_names(repo_root):
    from lib import envtree

    tree = envtree.load_seed_tree(repo_root)
    tree[""]["INGRESS_DOMAIN"] = "papaia.example.org"
    args = resolve.SetupArgs(
        config_dir=repo_root, env_name="itest", app_host="http://192.168.50.20",
        non_interactive=True, fresh_init=True,
    )
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_hostnames(tree, args)
    assert tree[""]["AUTH_HOST"] == "http://auth.papaia.example.org"


@pytest.mark.parametrize(
    "kwargs",
    [{"reverse_proxy_provider": "no_proxy"}, {"allow_direct_port_access": True}],
)
def test_direct_port_access_keeps_the_ports_of_the_addresses(repo_root, kwargs):
    tree = _resolved(repo_root, **kwargs)
    assert tree[""]["AUTH_HOST"] == "https://host.docker.internal:8110"
    assert tree[""]["OAUTH2_PROXY_PUBLIC_URL"] == "http://host.docker.internal:4180"


# ─────────────────────────────────────────────────────────────────────────
# the forward-auth callback in every proxy mode
# ─────────────────────────────────────────────────────────────────────────


def _oauth2(repo_root, provider, app_host, stored=None, allow_direct=False, **root):
    """OAUTH2_PROXY_PUBLIC_URL after a setup run over a stored root .env."""
    from lib import envtree

    tree = envtree.load_seed_tree(repo_root)
    tree[""].update({"PAPAIA_HOST": app_host, "REVERSE_PROXY_PROVIDER": provider, **root})
    if stored is not None:
        tree[""]["OAUTH2_PROXY_PUBLIC_URL"] = stored
    args = resolve.SetupArgs(
        config_dir=repo_root, env_name="itest", app_host=app_host, non_interactive=True,
        fresh_init=stored is None, allow_direct_port_access=allow_direct,
        reverse_proxy_provider=provider,
    )
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_hostnames(tree, args)
    tree = resolve.resolve_reverse_proxy(tree, args)
    return tree[""]["OAUTH2_PROXY_PUBLIC_URL"]


@pytest.mark.parametrize(
    "provider, allow_direct",
    [("external_proxy", False), ("no_proxy", False), ("internal_nginx", True),
     ("internal_nginx", False)],
)
def test_a_forward_auth_url_the_operator_chose_is_kept_in_every_mode(
    repo_root, provider, allow_direct
):
    chosen = "https://oauth2.example.com"
    url = _oauth2(repo_root, provider, "https://chat.example.com", chosen, allow_direct)
    assert url == chosen


@pytest.mark.parametrize("stored", [None, "", "https://chat.example.com:4180"])
def test_an_external_proxy_derives_the_forward_auth_host_without_a_port(repo_root, stored):
    # oauth2-proxy publishes no port there: the operator's proxy serves its host name.
    url = _oauth2(repo_root, "external_proxy", "https://chat.example.com", stored)
    assert url == "https://oauth2.chat.example.com"


def test_an_external_proxy_names_the_forward_auth_host_under_the_ingress_domain(repo_root):
    url = _oauth2(
        repo_root, "external_proxy", "https://chat.example.com", INGRESS_DOMAIN="example.com"
    )
    assert url == "https://oauth2.example.com"
    tree = {"": {"PAPAIA_HOST": "https://chat.example.com", "OAUTH2_PROXY_PUBLIC_URL": url,
                 "REVERSE_PROXY_PROVIDER": "external_proxy", "INGRESS_DOMAIN": "example.com",
                 "COMPOSE_PROFILES": "keycloak,oauth2-proxy"}}
    found = {r.host_key: r for r in ingress.core_routes(tree)}
    assert found["oauth2"].target == "http://oauth2-proxy:4180"


def test_an_external_proxy_without_a_domain_asks_for_one(repo_root):
    with pytest.raises(resolve.SetupError, match="OAUTH2_PROXY_PUBLIC_URL"):
        _oauth2(repo_root, "external_proxy", "https://192.168.50.20")
    chosen = "https://sso.example.org"
    assert _oauth2(repo_root, "external_proxy", "https://192.168.50.20", chosen) == chosen


@pytest.mark.parametrize(
    "provider, allow_direct", [("no_proxy", False), ("internal_nginx", True)]
)
def test_direct_port_access_follows_a_changed_app_host(repo_root, provider, allow_direct):
    # A port address an earlier run derived is no choice of the operator's.
    url = _oauth2(
        repo_root, provider, "https://new.example.com", "https://old.example.com:4180",
        allow_direct, PAPAIA_HOST="https://old.example.com",
    )
    assert url == "https://new.example.com:4180"


# ─────────────────────────────────────────────────────────────────────────
# the internal path of the Keycloak admin steps
# ─────────────────────────────────────────────────────────────────────────


def _edge_root(**extra: str) -> dict[str, str]:
    root = {
        "REVERSE_PROXY_PROVIDER": "internal_nginx",
        "COMPOSE_PROFILES": "keycloak,librechat,litellm,nginx",
        "AUTH_PROVIDER": "internal_keycloak",
        "DOCKER_NETWORK": "papaia-itest-net",
        "UID": "501",
        "GID": "20",
    }
    root.update(extra)
    return root


REPO = Path(__file__).resolve().parents[2]


def test_on_the_host_the_admin_steps_run_on_the_stack_network(monkeypatch, tmp_path):
    monkeypatch.setattr(common, "in_container", lambda: False)
    root = _edge_root()
    assert keycloak_admin_path.needs_oneshot(root)
    argv = keycloak_admin_path.oneshot_argv(root, tmp_path, REPO, ["keycloak-role-sync"])
    assert argv[:3] == ["docker", "run", "--rm"]
    assert argv[argv.index("--network") + 1] == "papaia-itest-net"
    assert argv[argv.index("--user") + 1] == "501:20"
    assert "--read-only" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    # No host port, no Docker socket, the checkout read-only.
    assert not any(a in ("-p", "--publish", "--network=host") for a in argv)
    assert not any("docker.sock" in a for a in argv)
    assert f"{REPO.resolve()}:{REPO.resolve()}:ro" in argv
    image = argv[argv.index("--entrypoint") + 2]
    assert "@sha256:" in image
    assert argv[-1] == "keycloak-role-sync"


def _preflight_argv(tmp_path) -> list[str]:
    argv = keycloak_admin_path.oneshot_argv(_edge_root(), tmp_path, REPO, ["realm-sync"])
    start = argv.index("--entrypoint")
    assert argv[start + 1] == "python3"
    return argv[start + 3 :]


def test_the_one_shot_container_checks_its_python_before_the_step(tmp_path):
    # The image's python3 runs this checkout's lib.cli: a missing PyYAML or an older
    # Python gives a message that names the image, not a traceback.
    args = _preflight_argv(tmp_path)
    assert args[0] == "-c"
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "yaml.py").write_text("raise ImportError('no yaml here')\n", encoding="utf-8")
    done = subprocess.run(
        [sys.executable, "-c", args[1], "--help"], cwd=broken, capture_output=True, text=True,
        check=False,
    )
    assert done.returncode == keycloak_admin_path.PREFLIGHT_FAILED
    assert "PyYAML" in done.stderr and "papaia-manager" in done.stderr
    assert "Traceback" not in done.stderr


def test_the_one_shot_container_then_runs_lib_cli(tmp_path):
    args = _preflight_argv(tmp_path)
    paths = ["--repo-root", str(REPO.resolve()), "--config-dir", str(tmp_path.resolve())]
    assert args[2:6] == paths
    done = subprocess.run(
        [sys.executable, "-c", args[1], "--help"], cwd=REPO / "tools", capture_output=True,
        text=True, check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "keycloak-role-sync" in done.stdout


def test_the_one_shot_container_reads_the_active_add_on_checkouts(tmp_path):
    # Realm sync reads the manifests of the active add-ons; they live outside the checkout.
    inst = Installation(tmp_path, [])
    assert _setup(inst) == 0
    elsewhere = tmp_path / "workspace"
    addon = _addon(elsewhere, "flow", {"flow-api": {"image": "x"}})
    inactive = {**_addon(elsewhere, "wiki", {"wiki": {"image": "x"}}), "active": False}
    manifest = deployment.load(inst.config)
    manifest["addons"] = [addon, inactive]
    deployment.save(inst.config, manifest)

    argv = keycloak_admin_path.oneshot_argv(_edge_root(), inst.config, REPO, ["realm-sync"])

    checkout = Path(addon["path"]).resolve()
    volumes = [argv[i + 1] for i, a in enumerate(argv) if a == "--volume"]
    assert f"{checkout}:{checkout}:ro" in volumes
    assert not any("wiki" in v for v in volumes)
    assert f"{inst.config.resolve()}:{inst.config.resolve()}" in volumes


def test_a_path_docker_cannot_mount_is_refused(tmp_path):
    odd = tmp_path / "a:b"
    odd.mkdir()
    with pytest.raises(keycloak_admin_path.AdminPathError, match="cannot mount"):
        keycloak_admin_path.oneshot_argv(_edge_root(), odd, REPO, ["realm-sync"])


def test_in_a_container_or_with_direct_ports_the_step_runs_in_place(monkeypatch):
    monkeypatch.setattr(common, "in_container", lambda: True)
    assert not keycloak_admin_path.needs_oneshot(_edge_root())
    monkeypatch.setattr(common, "in_container", lambda: False)
    direct = _edge_root(COMPOSE_PROFILES="keycloak,librechat,litellm")
    assert keycloak_admin_path.keycloak_published(direct)
    assert not keycloak_admin_path.needs_oneshot(direct)
    assert not keycloak_admin_path.needs_oneshot(_edge_root(AUTH_PROVIDER="external_oidc"))


def test_only_admin_steps_run_in_the_one_shot_container(tmp_path):
    with pytest.raises(keycloak_admin_path.AdminPathError):
        keycloak_admin_path.oneshot_argv(_edge_root(), tmp_path, REPO, ["setup"])
    with pytest.raises(keycloak_admin_path.AdminPathError):
        keycloak_admin_path.oneshot_argv(
            _edge_root(DOCKER_NETWORK="x; rm -rf /"), tmp_path, REPO, ["realm-sync"]
        )


def test_role_sync_on_the_host_runs_the_one_shot_container(monkeypatch, tmp_path):
    inst = Installation(tmp_path, [])
    assert _setup(inst) == 0
    monkeypatch.setattr(common, "in_container", lambda: False)
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(keycloak_admin_path.subprocess, "run", fake_run)
    code = cli.main(
        ["--repo-root", str(inst.repo), "--config-dir", str(inst.config), "keycloak-role-sync"]
    )
    assert code == 0
    assert len(calls) == 1 and calls[0][-1] == "keycloak-role-sync"
    assert calls[0][calls[0].index("--network") + 1] == "papaia-itest-net"
