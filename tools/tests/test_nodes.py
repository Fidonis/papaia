"""Enrolling nodes and talking to them: executors, keys, the join archive, the node CLI."""

from __future__ import annotations

import io
import json
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest
from install_helpers import Installation, run_cli
from test_topology import FULL, dmz_split, write_topology

from lib import cli, executor, link, nodes, topology
from lib.topology import Node

BASH = shutil.which("bash")


@pytest.fixture
def distributed(tmp_path: Path) -> Installation:
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    write_topology(inst.config, dmz_split())
    run_cli(inst.repo, inst.config, "render")
    return inst


def main(inst: Installation, *args: str) -> int:
    return cli.main(["--repo-root", str(inst.repo), "--config-dir", str(inst.config), *args])


# ─────────────────────────────────────────────────────────────────────────
# executors
# ─────────────────────────────────────────────────────────────────────────


def test_the_ssh_executor_trusts_only_the_pinned_host_and_its_own_key(tmp_path: Path):
    node = Node("edge", address="10.0.1.10", ssh_user="papaia", ssh_port=2222)
    key, known = tmp_path / "id", tmp_path / "known"
    argv = executor.ssh_argv(node, key, known, ["compose-up", "keycloak"])
    joined = " ".join(argv)
    for option in (
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        f"UserKnownHostsFile={known}",
        "GlobalKnownHostsFile=/dev/null",
        "IdentitiesOnly=yes",
        "PasswordAuthentication=no",
    ):
        assert option in joined
    assert argv[argv.index("-i") + 1] == str(key)
    assert argv[argv.index("-p") + 1] == "2222"
    assert argv[-4:] == ["papaia@10.0.1.10", "--", "compose-up", "keycloak"]


def test_the_ssh_executor_refuses_without_a_key_or_a_pinned_host(tmp_path: Path):
    ex = executor.SshExecutor(Node("edge", address="10.0.1.10"), config_dir=tmp_path)
    with pytest.raises(executor.ExecutorError, match="no SSH key"):
        ex.argv(["ping"])
    directory = executor.ssh_dir(tmp_path, "edge")
    directory.mkdir(parents=True)
    (directory / executor.KEY_NAME).write_text("key")
    with pytest.raises(executor.ExecutorError, match="not pinned"):
        ex.argv(["ping"])


@pytest.mark.parametrize("word", ["a;b", "$(id)", "../x", "-d", "two words", ""])
def test_executors_refuse_words_the_shim_would_refuse(tmp_path: Path, word: str):
    ex = executor.LocalExecutor(
        Node("x", executor="local"), repo_root=tmp_path, config_dir=tmp_path
    )
    with pytest.raises(executor.ExecutorError):
        ex.run(["compose-up", word])


def test_the_local_executor_goes_through_the_shim(tmp_path: Path):
    ex = executor.LocalExecutor(
        Node("internal", executor="local"), repo_root=tmp_path / "repo", config_dir=tmp_path
    )
    argv, env = ex.argv(["compose-up", "librechat"])
    assert argv[1:3] == [str(tmp_path / "repo" / "tools" / "papaia-ctl"), "node-shell"]
    assert f"--controller-config={tmp_path}" in argv and "--node=internal" in argv
    assert env["SSH_ORIGINAL_COMMAND"] == "compose-up librechat"


@pytest.mark.skipif(BASH is None, reason="bash is not available")
def test_the_controller_runs_its_node_through_the_real_entrypoint(
    distributed: Installation, monkeypatch
):
    # The checkout copy carries src/ only; the entrypoint and its libraries are this
    # checkout's.
    tools = Path(__file__).resolve().parents[1]
    shutil.copytree(
        tools,
        distributed.repo / "tools",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("tests", "__pycache__"),
    )
    ex = nodes.executor(distributed.config, distributed.repo, "internal")
    done = ex.run(["ping"], capture=True, timeout=60)
    assert done.ok, done.stderr
    assert done.stdout.startswith("pong internal ")
    refused = ex.run(["compose-up", "keycloak"], capture=True, timeout=60)
    assert refused.returncode == 2
    assert "does not run on node 'internal'" in refused.stderr
    audit = (distributed.config / "nodes" / "internal" / "audit.log").read_text()
    assert "verb=ping" in audit and "verb=compose-up" in audit


# ─────────────────────────────────────────────────────────────────────────
# enrolment
# ─────────────────────────────────────────────────────────────────────────


def test_the_authorized_keys_line_forces_the_shim():
    topo = dmz_split()
    line = nodes.authorized_keys_line(topo, topo.nodes["edge"], "ssh-ed25519 AAAA test")
    assert line == (
        'restrict,from="10.0.2.10",command="bash /srv/papaia-node/checkout/tools/papaia-ctl'
        ' node-shell --node-root=/srv/papaia-node" ssh-ed25519 AAAA test'
    )


def test_the_controller_key_stays_private(distributed: Installation):
    key, public = nodes.ensure_keypair(distributed.config, "edge")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert public.startswith("ssh-ed25519 ")
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    # Not part of anything a node receives.
    for path in topology.bundle_dir(distributed.config, "edge").rglob("*"):
        if path.is_file():
            assert "PRIVATE KEY-----" not in path.read_text(errors="replace") or path.name in (
                "node.key",
                "node.pem",
            )


def test_the_join_archive_carries_what_the_node_needs(distributed: Installation):
    data = nodes.join_archive(distributed.config, distributed.repo, "edge")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = {m.name: m for m in tar.getmembers()}
        prefix = "papaia-join-edge/"
        assert set(members) == {
            prefix + name
            for name in (
                "install.sh",
                "checkout.tar",
                "authorized_keys",
                "controller.fingerprint",
                "README.txt",
            )
        }
        assert members[prefix + "install.sh"].mode == 0o755
        assert members[prefix + "authorized_keys"].mode == 0o600
        script = tar.extractfile(prefix + "install.sh").read().decode()
        keys = tar.extractfile(prefix + "authorized_keys").read().decode()
        checkout = tar.extractfile(prefix + "checkout.tar").read()
    assert "NODE='edge'" in script and "ROOT='/srv/papaia-node'" in script
    assert "@" not in script.split("set -euo pipefail", 1)[1].split("fail()", 1)[0]
    assert keys.startswith('restrict,from="10.0.2.10",command="bash /srv/papaia-node/checkout')
    with tarfile.open(fileobj=io.BytesIO(checkout)) as tar:
        names = set(tar.getnames())
    assert "src/docker-compose.yml" in names
    assert not any(n.endswith("/.env") or n == ".env" for n in names)


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_the_rendered_install_script_passes_shellcheck(distributed: Installation, tmp_path: Path):
    data = nodes.join_archive(distributed.config, distributed.repo, "edge")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        script = tar.extractfile("papaia-join-edge/install.sh").read()
    path = tmp_path / "install.sh"
    path.write_bytes(script)
    done = subprocess.run(
        ["shellcheck", "--severity=warning", str(path)], capture_output=True, text=True
    )
    assert done.returncode == 0, done.stdout


def test_a_checkout_without_git_leaves_out_what_setup_wrote(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "src" / "ai").mkdir(parents=True)
    (repo / "src" / "docker-compose.yml").write_text("x")
    (repo / "src" / ".env").write_text("SECRET=1")
    (repo / "src" / "ai" / ".env").write_text("SECRET=2")
    (repo / "tools" / "__pycache__").mkdir(parents=True)
    (repo / "tools" / "__pycache__" / "x.pyc").write_text("x")
    with tarfile.open(fileobj=io.BytesIO(nodes.checkout_archive(repo))) as tar:
        assert tar.getnames() == ["src/docker-compose.yml"]


def test_pinning_requires_a_real_fingerprint(distributed: Installation):
    with pytest.raises(nodes.NodeError, match="not a SHA256"):
        nodes.pin_host_key(distributed.config, dmz_split().nodes["edge"], "MD5:aa:bb")


def test_host_key_fingerprints_are_read_from_a_scan(tmp_path: Path):
    key = tmp_path / "host"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    public = key.with_suffix(".pub").read_text().split()
    found = nodes.host_key_fingerprints([f"10.0.1.10 {public[0]} {public[1]}"])
    assert found[0][0] == "ssh-ed25519" and found[0][1].startswith("SHA256:")


# ─────────────────────────────────────────────────────────────────────────
# node CLI
# ─────────────────────────────────────────────────────────────────────────


def test_node_commands_refuse_a_single_host(tmp_path: Path, capsys):
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    assert main(inst, "node-list") == 2
    assert "runs on one host" in capsys.readouterr().err
    assert main(inst, "node-register", "--name=edge", "--address=10.0.1.10") == 2
    assert "topology" not in (inst.config / "deployment.yaml").read_text()


def test_registering_a_node_adds_it_with_its_key_and_bundle(distributed: Installation):
    assert (
        main(
            distributed,
            "node-register",
            "--name=gpu",
            "--address=10.0.3.10",
            "--ssh-port=2222",
            "--gpu=nvidia",
        )
        == 0
    )
    topo = topology.load_config(distributed.config)
    assert topo.nodes["gpu"].ssh_port == 2222 and topo.nodes["gpu"].gpu == "nvidia"
    assert (executor.ssh_dir(distributed.config, "gpu") / executor.KEY_NAME).is_file()
    assert (link.leaf_dir(distributed.config, "gpu") / "node.crt").is_file()
    assert topology.bundle_dir(distributed.config, "gpu").is_dir()


def test_a_node_that_breaks_the_topology_is_not_added(distributed: Installation, capsys):
    before = (distributed.config / "deployment.yaml").read_text()
    assert main(distributed, "node-register", "--name=Bad_Name", "--address=10.0.3.10") == 2
    assert "names are lowercase" in capsys.readouterr().err
    assert (distributed.config / "deployment.yaml").read_text() == before


def test_the_controller_cannot_be_enrolled_or_removed(distributed: Installation, capsys):
    assert main(distributed, "node-register", "--name=internal", "--address=10.0.2.10") == 2
    assert main(distributed, "node-unregister", "--name=internal") == 2
    assert "controller" in capsys.readouterr().err


def test_a_node_with_services_cannot_be_removed(distributed: Installation, capsys):
    assert main(distributed, "node-unregister", "--name=edge") == 2
    assert "still runs" in capsys.readouterr().err


def test_an_empty_node_is_removed_with_its_keys(distributed: Installation):
    main(distributed, "node-register", "--name=spare", "--address=10.0.4.10")
    assert (distributed.config / "nodes" / "spare").is_dir()
    assert main(distributed, "node-unregister", "--name=spare") == 0
    assert "spare" not in topology.load_config(distributed.config).nodes
    assert not (distributed.config / "nodes" / "spare").exists()


def test_node_list_reports_each_node(distributed: Installation, capsys):
    assert main(distributed, "node-list", "--json") == 0
    rows = {r["name"]: r for r in json.loads(capsys.readouterr().out)}
    assert rows["internal"]["controller"] is True
    assert "keycloak" in rows["edge"]["services"]
    assert rows["edge"]["host_key_pinned"] is False


def test_the_join_bundle_is_written_privately(distributed: Installation, tmp_path: Path):
    output = tmp_path / "join.tar.gz"
    assert main(distributed, "node-join-bundle", "--name=edge", f"--output={output}") == 0
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.stat().st_size > 0


@pytest.mark.parametrize("fmt", ["table", "json", "csv"])
def test_topology_firewall_prints_the_matrix(distributed: Installation, capsys, fmt: str):
    assert main(distributed, "topology-firewall", f"--format={fmt}") == 0
    out = capsys.readouterr().out
    assert "7443" in out
    if fmt == "json":
        rules = json.loads(out)
        assert {(r["from"], r["to"], r["port"]) for r in rules} == {
            ("internal", "edge", 22),
            ("internal", "edge", 7443),
            ("edge", "internal", 7443),
        }


def test_renewing_a_link_certificate_keeps_its_names(distributed: Installation):
    names = (link.leaf_dir(distributed.config, "edge") / "names").read_text()
    before = (link.leaf_dir(distributed.config, "edge") / "node.crt").read_text()
    assert main(distributed, "node-renew-link", "--name=edge") == 0
    after = (link.leaf_dir(distributed.config, "edge") / "node.crt").read_text()
    assert after != before
    assert (link.leaf_dir(distributed.config, "edge") / "names").read_text() == names
    bundle = topology.bundle_dir(distributed.config, "edge") / "link" / "node.crt"
    assert bundle.read_text() == after


def test_a_push_to_a_node_without_a_key_fails_with_a_hint(distributed: Installation, capsys):
    key = executor.ssh_dir(distributed.config, "edge") / executor.KEY_NAME
    key.unlink(missing_ok=True)
    assert main(distributed, "node-push", "--name=edge") == 3
    assert "node add edge" in capsys.readouterr().err
