"""The topology model of a distributed installation: catalogue, validation, presets and
the per-node bundles a render projects out of the config tree."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from install_helpers import REPO, Installation, run_cli

from lib import cli, common, deployment, envtree, keycloak_role_sync, npm_provision, topology
from lib.topology import Node, Topology

# Every service switched on, public URLs on subdomains: what a distributed installation
# behind the bundled proxy looks like.
FULL = [
    "--app-host=https://papaia.example.org",
    "--auth-host=https://auth.papaia.example.org",
    "--librechat-host=https://chat.example.org",
    "--litellm-host=https://llm.example.org",
    "--npm-admin-host=https://npm.example.org",
    "--enable-web-search=true",
    "--enable-local-ai=true",
    "--localai-variant=cpu",
    "--localai-host=https://localai.example.org",
    "--enable-manager=true",
    "--manager-host=https://manager.example.org",
    "--enable-rag=true",
    "--qdrant-host=https://qdrant.example.org",
    "--enable-smtp=true",
    "--smtp-host=smtp.example.org",
    "--smtp-port=587",
    "--smtp-security=starttls",
    "--smtp-no-auth",
    "--smtp-from=noreply@example.org",
]

ALL_PROFILES = [
    "keycloak",
    "oauth2-proxy",
    "librechat",
    "litellm",
    "nginx",
    "librechat-websearch",
    "localai",
    "manager",
    "rag",
    "smtp",
]


def two_nodes(**placement: str) -> Topology:
    return Topology(
        mode=topology.DISTRIBUTED,
        controller="internal",
        nodes={
            "internal": Node("internal", address="10.0.2.10", executor="local"),
            "edge": Node("edge", address="10.0.1.10", executor="ssh"),
        },
        placement=dict(placement),
    )


def dmz_split() -> Topology:
    return two_nodes(**topology.preset_placement("dmz-split", "edge"))


def write_topology(config: Path, topo: Topology) -> None:
    manifest = deployment.load(config)
    manifest["topology"] = topo.to_dict()
    deployment.save(config, manifest)


@pytest.fixture
def full(tmp_path: Path) -> Installation:
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    return inst


# ─────────────────────────────────────────────────────────────────────────
# catalogue
# ─────────────────────────────────────────────────────────────────────────


def test_every_core_profile_belongs_to_exactly_one_service():
    profiles = {p for s in topology.compose_services(REPO) for p in s.profiles}
    for profile in profiles:
        owners = [n for n, spec in topology.CATALOGUE.items() if profile in spec.profiles]
        assert len(owners) == 1, f"profile '{profile}' belongs to {owners or 'no service'}"


def test_every_service_env_dir_belongs_to_exactly_one_service():
    seed_dirs = {d for d in envtree.discover_env_examples(REPO) if d}
    for rel_dir in seed_dirs:
        owners = [n for n, spec in topology.CATALOGUE.items() if rel_dir in spec.env_dirs]
        assert len(owners) == 1, f"{rel_dir}/.env belongs to {owners or 'no service'}"
    claimed = {d for spec in topology.CATALOGUE.values() for d in spec.env_dirs}
    assert claimed <= seed_dirs, (
        f"catalogue names env dirs that do not exist: {claimed - seed_dirs}"
    )


def test_the_catalogue_profiles_exist_in_the_compose_files():
    profiles = {p for s in topology.compose_services(REPO) for p in s.profiles}
    for spec in topology.CATALOGUE.values():
        assert set(spec.profiles) <= profiles, spec.name


def test_start_order_puts_identity_first_and_the_proxy_last():
    groups = {name: spec.start_group for name, spec in topology.CATALOGUE.items()}
    assert groups["keycloak"] < groups["litellm"] < groups["librechat"] < groups["nginx"]
    assert groups["nginx"] == max(groups.values())


# ─────────────────────────────────────────────────────────────────────────
# parsing
# ─────────────────────────────────────────────────────────────────────────


def test_a_missing_block_is_a_single_node_installation():
    topo = topology.load({"customer": "x"})
    assert topo.mode == topology.SINGLE
    assert not topo.distributed


def test_a_block_round_trips():
    topo = dmz_split()
    assert topology.parse(topo.to_dict()) == topo


def test_defaults_are_filled_in():
    topo = topology.parse(
        {
            "mode": "distributed",
            "controller": "a",
            "nodes": {"a": {"address": "10.0.0.1", "executor": "local"}, "b": {"address": "b"}},
        }
    )
    edge = topo.nodes["b"]
    assert (edge.executor, edge.ssh_user, edge.ssh_port, edge.root) == (
        "ssh",
        "papaia",
        22,
        "/srv/papaia-node",
    )
    assert edge.config_dir == "/srv/papaia-node/config"
    assert topo.link_port == 7443


@pytest.mark.parametrize(
    "raw",
    [
        "distributed",
        {"mode": "cluster"},
        {"mode": "distributed", "nodes": ["a", "b"]},
        {"mode": "distributed", "placement": ["nginx"]},
        {"mode": "distributed", "link": {"port": "seven"}},
        {"mode": "distributed", "nodes": {"a": {"ssh": {"port": True}}}},
    ],
)
def test_a_malformed_block_is_refused(raw):
    with pytest.raises(topology.TopologyError):
        topology.parse(raw)


def test_unlisted_services_stay_on_the_controller():
    topo = dmz_split()
    assert topo.node_of("librechat") == "internal"
    assert topo.node_of("keycloak") == "edge"


# ─────────────────────────────────────────────────────────────────────────
# presets
# ─────────────────────────────────────────────────────────────────────────


def test_dmz_split_puts_ingress_identity_mail_and_llm_gateway_at_the_edge():
    assert topology.preset_placement("dmz-split", "edge") == {
        "nginx": "edge",
        "keycloak": "edge",
        "smtp": "edge",
        "litellm": "edge",
    }


def test_dmz_edge_keeps_identity_internal():
    placement = topology.preset_placement("dmz-edge", "dmz")
    assert placement == {"nginx": "dmz", "litellm": "dmz"}


def test_an_unknown_preset_is_refused():
    with pytest.raises(topology.TopologyError, match="unknown preset"):
        topology.preset_placement("dmz", "edge")


@pytest.mark.parametrize("preset", sorted(topology.PRESETS))
def test_both_presets_validate(preset):
    topo = two_nodes(**topology.preset_placement(preset, "edge"))
    found = topology.validate(topo, active_profiles=ALL_PROFILES)
    assert found.ok, found.errors


# ─────────────────────────────────────────────────────────────────────────
# validation
# ─────────────────────────────────────────────────────────────────────────


def errors(topo: Topology, profiles=None, env=None, repo_root=None) -> list[str]:
    return topology.validate(
        topo, active_profiles=profiles or ALL_PROFILES, env=env, repo_root=repo_root
    ).errors


def warnings(topo: Topology, profiles=None, env=None) -> list[str]:
    return topology.validate(topo, active_profiles=profiles or ALL_PROFILES, env=env).warnings


def test_single_mode_needs_no_nodes():
    assert topology.validate(Topology(), active_profiles=ALL_PROFILES).ok


def test_single_mode_with_a_placement_warns_that_it_is_ignored():
    found = topology.validate(Topology(placement={"nginx": "x"}), active_profiles=ALL_PROFILES)
    assert found.ok and "ignored" in found.warnings[0]


@pytest.mark.parametrize("service", ["manager", "rag"])
def test_manager_and_rag_must_stay_on_the_controller(service):
    found = errors(two_nodes(**{service: "edge"}))
    assert any(f"'{service}' must run on the controller" in e for e in found)


def test_web_search_must_run_with_librechat():
    assert any(
        "'websearch' must run on the node of 'librechat'" in e
        for e in errors(two_nodes(librechat="edge"))
    )
    assert errors(two_nodes(librechat="edge", websearch="edge")) == []


def test_unknown_service_and_unknown_node_are_named():
    found = errors(two_nodes(mailer="edge", nginx="dmz"))
    assert any("unknown service 'mailer'" in e for e in found)
    assert any("unknown node 'dmz'" in e for e in found)


def test_placing_an_inactive_service_is_a_warning():
    found = topology.validate(
        two_nodes(localai="edge"), active_profiles=["keycloak", "librechat", "litellm"]
    )
    assert found.ok
    assert any("'localai' has no effect" in w for w in found.warnings)


def test_the_controller_must_exist_and_be_local():
    topo = two_nodes()
    assert any(
        "not one of the nodes" in e
        for e in errors(Topology(mode="distributed", controller="x", nodes=topo.nodes))
    )
    remote_controller = Topology(
        mode="distributed",
        controller="edge",
        nodes=topo.nodes,
    )
    found = errors(remote_controller)
    assert any("must use the 'local' executor" in e for e in found)
    assert any("uses the 'local' executor but is not the controller" in e for e in found)


def test_one_node_is_not_distributed():
    topo = Topology(
        mode="distributed",
        controller="a",
        nodes={"a": Node("a", address="10.0.0.1", executor="local")},
    )
    assert any("at least two nodes" in e for e in errors(topo))


@pytest.mark.parametrize(
    "node, fragment",
    [
        (Node("Edge", address="10.0.1.10"), "names are lowercase"),
        (Node("edge", address=""), "an address is required"),
        (Node("edge", address="10.0.1.10; rm -rf /"), "is not a host name"),
        (Node("edge", address="10.0.1.10", executor="docker"), "executor must be one of"),
        (Node("edge", address="10.0.1.10", ssh_user="Root!"), "not a valid user name"),
        (Node("edge", address="10.0.1.10", ssh_port=70000), "out of range"),
        (Node("edge", address="10.0.1.10", root="relative/dir"), "absolute path"),
        (Node("edge", address="10.0.1.10", gpu="tpu"), "gpu must be one of"),
    ],
)
def test_node_fields_are_checked(node: Node, fragment: str):
    topo = Topology(
        mode="distributed",
        controller="internal",
        nodes={
            "internal": Node("internal", address="10.0.2.10", executor="local"),
            node.name: node,
        },
    )
    assert any(fragment in e for e in errors(topo)), errors(topo)


def test_localai_on_a_node_without_the_gpu_is_refused():
    topo = two_nodes(localai="edge")
    topo.nodes["edge"] = Node("edge", address="10.0.1.10", gpu="none")
    env = {"LOCALAI_IMAGE_VARIANT": "nvidia-cuda-13"}
    assert any("has gpu: none" in e for e in errors(topo, env=env))


def test_localai_on_a_node_with_unknown_hardware_is_a_warning():
    env = {"LOCALAI_IMAGE_VARIANT": "hipblas"}
    found = warnings(two_nodes(localai="edge"), env=env)
    assert any("not recorded" in w for w in found)


def test_localai_on_the_cpu_needs_no_hardware():
    env = {"LOCALAI_IMAGE_VARIANT": "cpu"}
    topo = two_nodes(localai="edge")
    topo.nodes["edge"] = Node("edge", address="10.0.1.10", gpu="none")
    assert errors(topo, env=env) == []


def test_the_link_port_must_not_collide_with_a_published_port():
    env = {"LIBRECHAT_EXT_PORT": "7443", "HOST_IP": "0.0.0.0"}
    topo = two_nodes(**topology.preset_placement("dmz-split", "edge"))
    found = errors(topo, env=env, repo_root=REPO)
    assert any(
        "collides with the port 'librechat' publishes on node 'internal'" in e for e in found
    )


def test_the_link_port_must_be_unprivileged():
    topo = Topology(**{**dmz_split().__dict__, "link_port": 443})
    assert any("between 1024 and 65535" in e for e in errors(topo))


def test_public_urls_must_be_host_names_without_a_port_behind_the_bundled_proxy():
    env = {
        "AUTH_HOST": "https://auth.example.org",
        "LITELLM_PUBLIC_URL": "https://papaia.example.org:8200",
        "DOMAIN_SERVER": "https://chat.example.org",
    }
    found = errors(dmz_split(), env=env)
    assert len([e for e in found if "public URL" in e]) == 1
    assert "LiteLLM" in next(e for e in found if "public URL" in e)


def test_without_the_bundled_proxy_a_warning_points_at_the_external_one():
    profiles = [p for p in ALL_PROFILES if p != "nginx"]
    assert any("external proxy" in w for w in warnings(two_nodes(), profiles=profiles))


def test_relay_away_from_keycloak_is_a_warning():
    assert any("SMTP relay" in w for w in warnings(two_nodes(keycloak="edge")))


# ─────────────────────────────────────────────────────────────────────────
# cluster-wide profiles
# ─────────────────────────────────────────────────────────────────────────


def test_cluster_profiles_fall_back_to_compose_profiles():
    assert common.cluster_profiles({"COMPOSE_PROFILES": "a,b"}) == {"a", "b"}


def test_cluster_profiles_prefer_the_active_modules_of_a_node():
    env = {"COMPOSE_PROFILES": "keycloak", "PAPAIA_ACTIVE_MODULES": "keycloak,rag"}
    assert common.cluster_profiles(env) == {"keycloak", "rag"}
    assert keycloak_role_sync._active_profile_clients(env) == {
        "mcp-qdrant",
        "mcp-qdrant-ingest",
    }


def test_npm_provisioning_reads_the_librechat_url_from_the_node_root():
    tree = {
        "": {"LIBRECHAT_PUBLIC_URL": "https://chat.example.org"},
        "ai/librechat": {"DOMAIN_SERVER": "http://host.docker.internal:8000"},
    }
    assert npm_provision._public_url(tree, "ai/librechat", "DOMAIN_SERVER") == (
        "https://chat.example.org"
    )
    del tree[""]["LIBRECHAT_PUBLIC_URL"]
    assert npm_provision._public_url(tree, "ai/librechat", "DOMAIN_SERVER") == (
        "http://host.docker.internal:8000"
    )


# ─────────────────────────────────────────────────────────────────────────
# projection
# ─────────────────────────────────────────────────────────────────────────


def bundle_env(inst: Installation, node: str, rel: str = "") -> dict[str, str]:
    path = topology.bundle_dir(inst.config, node) / rel / ".env"
    return common.parse_env_file(path)


def bundle_files(inst: Installation, node: str) -> list[Path]:
    return [p for p in topology.bundle_dir(inst.config, node).rglob("*") if p.is_file()]


def project(inst: Installation, topo: Topology) -> list[topology.NodeBundle]:
    write_topology(inst.config, topo)
    return topology.project(inst.config, inst.repo, topo)


def test_single_mode_writes_no_bundle(full: Installation):
    assert topology.project(full.config, full.repo, Topology()) == []
    assert not (full.config / "nodes").exists()


def test_each_node_starts_only_its_own_profiles(full: Installation):
    project(full, dmz_split())
    edge = bundle_env(full, "edge")
    internal = bundle_env(full, "internal")
    cluster = common.parse_env_file(full.config / ".env")["COMPOSE_PROFILES"]
    assert set(edge["COMPOSE_PROFILES"].split(",")) == {
        "keycloak",
        "oauth2-proxy",
        "litellm",
        "smtp",
        "nginx",
        "link-gateway",
    }
    assert set(internal["COMPOSE_PROFILES"].split(",")) == {
        "librechat",
        "librechat-websearch",
        "localai",
        "manager",
        "rag",
        "link-gateway",
    }
    # In the installation's own order, so a bundle diff only shows real changes.
    order = cluster.split(",")
    for env in (edge, internal):
        profiles = [p for p in env["COMPOSE_PROFILES"].split(",") if p != "link-gateway"]
        assert profiles == sorted(profiles, key=order.index)
    assert edge["PAPAIA_ACTIVE_MODULES"] == internal["PAPAIA_ACTIVE_MODULES"] == cluster


def test_a_remote_node_gets_its_own_directories_and_a_local_bind_address(full: Installation):
    project(full, dmz_split())
    edge = bundle_env(full, "edge")
    assert edge["PAPAIA_CONFIG_DIR"] == "/srv/papaia-node/config"
    assert edge["PAPAIA_BACKUP_DIR"] == "/srv/papaia-node/backup"
    assert edge["PAPAIA_NODE"] == "edge"
    assert edge["HOST_IP"] == "127.0.0.1"
    # The controller keeps the paths of the full tree: the manager mounts it.
    internal = bundle_env(full, "internal")
    assert internal["PAPAIA_CONFIG_DIR"] == str(full.config)


def test_a_node_gets_only_the_env_files_of_its_services(full: Installation):
    project(full, dmz_split())
    edge_dirs = {
        p.parent.relative_to(topology.bundle_dir(full.config, "edge")).as_posix()
        for p in bundle_files(full, "edge")
        if p.name == ".env"
    }
    assert edge_dirs == {
        ".",
        "infra/keycloak",
        "infra/nginx",
        "infra/oauth2-proxy",
        "ai/litellm",
        "infra/smtp-relay",
    }


def test_a_remote_node_gets_the_rendered_configuration_of_its_services(full: Installation):
    project(full, dmz_split())
    edge = topology.bundle_dir(full.config, "edge")
    assert (edge / "ai/litellm/config.yaml").is_file()
    assert (edge / "infra/keycloak/keycloak.conf").is_file()
    assert (edge / "infra/keycloak/realm-import/papaia-realm.json").is_file()
    assert (edge / "infra/smtp-relay/upstream-password").is_file()
    assert not (edge / "ai/librechat/librechat.yaml").exists()
    # The proxy's database and certificates are state on the edge, never shipped.
    assert not (edge / "infra/nginx/nginx-data").exists()
    manifest = json.loads((edge / "node.json").read_text(encoding="utf-8"))
    assert "infra/nginx/nginx-data" in manifest["state_dirs"]
    assert "keycloak" in manifest["compose_services"]
    assert "librechat" not in manifest["compose_services"]


def test_no_bundle_contains_the_ca_key(full: Installation):
    certs = full.config / "certs"
    certs.mkdir(exist_ok=True)
    for name in ("local-ca.key", "local-ca.crt", "keycloak.key", "keycloak.crt"):
        (certs / name).write_text(f"{name}\n", encoding="utf-8")
    project(full, dmz_split())
    for node in ("edge", "internal"):
        names = {p.name for p in bundle_files(full, node)}
        assert "local-ca.key" not in names
        assert "local-ca.crt" in names
    assert (topology.bundle_dir(full.config, "edge") / "certs/keycloak.key").is_file()
    assert not (topology.bundle_dir(full.config, "internal") / "certs/keycloak.key").exists()


def _secrets_by_dir(inst: Installation) -> dict[str, set[str]]:
    seed = envtree.load_seed_tree(inst.repo)
    tree = envtree.load_config_dir_tree(inst.config, inst.repo)
    found: dict[str, set[str]] = {}
    for rel_dir, values in seed.items():
        for key, seed_value in values.items():
            value = tree.get(rel_dir, {}).get(key, "")
            if (
                common.marks_generated_secret(seed_value)
                and value
                and not common.is_placeholder(value)
            ):
                found.setdefault(rel_dir, set()).add(value)
    return found


@pytest.mark.parametrize("preset", sorted(topology.PRESETS))
def test_no_bundle_contains_a_secret_of_another_node(full: Installation, preset: str):
    topo = two_nodes(**topology.preset_placement(preset, "edge"))
    project(full, topo)
    by_dir = _secrets_by_dir(full)
    active = topology.active_services(
        common.parse_env_file(full.config / ".env")["COMPOSE_PROFILES"].split(",")
    )
    for node in topo.nodes:
        own_dirs = {
            d for s in topo.services_on(node, active) for d in topology.CATALOGUE[s].env_dirs
        }
        own = {v for d in own_dirs for v in by_dir.get(d, set())}
        referenced = topology.referenced_variables(
            topology.services_of(full.repo, topo.services_on(node, active))
        )
        root_seed = envtree.load_seed_tree(full.repo)[""]
        root_tree = envtree.load_config_dir_tree(full.config, full.repo)[""]
        own |= {root_tree[k] for k in referenced if k in root_seed and k in root_tree}
        foreign = {v for d, values in by_dir.items() for v in values} - own
        assert foreign, "the fixture should leave something foreign for every node"
        for path in bundle_files(full, node):
            text = path.read_text(encoding="utf-8", errors="replace")
            leaked = [v for v in foreign if v in text]
            assert not leaked, f"{node}: {path.name} carries secrets of another node"


def test_root_secrets_are_blanked_where_no_service_uses_them(full: Installation):
    project(full, dmz_split())
    assert bundle_env(full, "internal")["OAUTH2_PROXY_CLIENT_SECRET"] == ""
    assert bundle_env(full, "edge")["OAUTH2_PROXY_CLIENT_SECRET"] != ""


def test_every_node_knows_the_librechat_url(full: Installation):
    project(full, dmz_split())
    assert bundle_env(full, "edge")["LIBRECHAT_PUBLIC_URL"] == "https://chat.example.org"


def test_a_removed_node_loses_its_bundle(full: Installation):
    topo = dmz_split()
    project(full, topo)
    assert topology.bundle_dir(full.config, "edge").is_dir()
    moved = Topology(
        mode=topo.mode,
        controller=topo.controller,
        nodes={
            "internal": topo.nodes["internal"],
            "dmz": Node("dmz", address="10.0.1.11"),
        },
        placement=topology.preset_placement("dmz-split", "dmz"),
    )
    project(full, moved)
    assert not topology.bundle_dir(full.config, "edge").exists()
    assert topology.bundle_dir(full.config, "dmz").is_dir()


def test_projection_is_repeatable(full: Installation):
    project(full, dmz_split())
    first = {p: p.read_bytes() for p in bundle_files(full, "edge")}
    project(full, dmz_split())
    assert {p: p.read_bytes() for p in bundle_files(full, "edge")} == first


# ─────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────


def test_render_projects_the_bundles_in_distributed_mode(full: Installation):
    write_topology(full.config, dmz_split())
    run_cli(full.repo, full.config, "render")
    assert topology.bundle_dir(full.config, "edge").is_dir()


def test_a_repeated_setup_keeps_the_topology_and_projects(full: Installation):
    write_topology(full.config, dmz_split())
    full.setup()
    assert deployment.load(full.config)["topology"]["mode"] == "distributed"
    assert topology.bundle_dir(full.config, "internal").is_dir()


def test_render_refuses_a_broken_topology(full: Installation, capsys):
    write_topology(full.config, two_nodes(manager="edge"))
    code = cli.main(["--repo-root", str(full.repo), "--config-dir", str(full.config), "render"])
    assert code == 3
    assert "'manager' must run on the controller" in capsys.readouterr().err
    assert not (full.config / "nodes").exists()


def test_topology_validate_exit_codes(full: Installation, capsys):
    argv = ["--repo-root", str(full.repo), "--config-dir", str(full.config), "topology-validate"]
    assert cli.main(argv) == 0
    assert "single" in capsys.readouterr().out
    write_topology(full.config, dmz_split())
    assert cli.main(argv) == 0
    write_topology(full.config, two_nodes(rag="edge"))
    assert cli.main(argv) == 2


def test_topology_show_lists_where_each_service_runs(full: Installation, capsys):
    write_topology(full.config, dmz_split())
    argv = ["--repo-root", str(full.repo), "--config-dir", str(full.config)]
    assert cli.main([*argv, "topology-show", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["services"]["keycloak"] == "edge"
    assert document["services"]["librechat"] == "internal"
    assert cli.main([*argv, "topology-show"]) == 0
    table = capsys.readouterr().out
    assert "ssh papaia@10.0.1.10" in table


_MODE_HARNESS = """
set -euo pipefail
CONFIG_DIR="@CONFIG@"
py_cli() { echo "py_cli $*" >> "@LOG@"; echo distributed; }
source "@TOPOLOGY@"
_topology_mode
"""


def _mode(tmp_path: Path, manifest: dict | None) -> tuple[str, str]:
    import shutil
    import subprocess

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    config = tmp_path / "config"
    config.mkdir(exist_ok=True)
    if manifest is not None:
        (config / "deployment.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    log = tmp_path / "py.log"
    log.write_text("", encoding="utf-8")
    script = (
        _MODE_HARNESS.replace("@CONFIG@", config.as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@TOPOLOGY@", (REPO / "tools/lib/sh/lifecycle.sh").as_posix())
    )
    done = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=True)
    return done.stdout, log.read_text(encoding="utf-8")


@pytest.mark.parametrize("manifest", [None, {"customer": "x", "addons": []}])
def test_a_single_node_installation_is_recognised_without_python(tmp_path: Path, manifest):
    mode, calls = _mode(tmp_path, manifest)
    assert mode == "single"
    assert calls == ""


def test_a_topology_block_is_handed_to_python(tmp_path: Path):
    mode, calls = _mode(tmp_path, {"customer": "x", "topology": {"mode": "distributed"}})
    assert mode == "distributed"
    assert "topology-mode" in calls
