"""The forced command of a node's SSH key: what gets through, and what never does."""

from __future__ import annotations

import io
import json
import os
import random
import stat
import tarfile
from pathlib import Path

import pytest
from install_helpers import Installation
from test_topology import FULL, dmz_split, write_topology

from lib import node_shell, nodes, topology
from lib.node_shell import Context, Refused

# ─────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────


class Recorder:
    """Stands in for running a command: records the argv and returns `code`."""

    def __init__(self, code: int = 0):
        self.calls: list[list[str]] = []
        self.code = code

    def __call__(self, argv, **kwargs) -> int:
        self.calls.append(list(argv))
        return self.code


def remote_node(tmp_path: Path, name: str = "edge", *, checkout: Path | None = None) -> Context:
    root = tmp_path / "node-root"
    (root / "config").mkdir(parents=True)
    (root / "releases").mkdir()
    (root / "node-name").write_text(f"{name}\n", encoding="utf-8")
    if checkout is not None:
        os.symlink(checkout, root / "checkout")
    ctx = node_shell.context_from_args(
        ["--repo-root", str(root / "checkout"), f"--node-root={root}"]
    )
    ctx.run = Recorder()
    return ctx


def tar_bytes(entries: list[tuple[str, bytes | None, int]], *, kind=tarfile.REGTYPE) -> bytes:
    """A tar archive of (name, content, mode); content None makes a directory."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.type = kind
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def run(ctx: Context, command: str, stdin: bytes = b"") -> int:
    ctx.stdin = io.BytesIO(stdin)
    return node_shell.execute(ctx, command)


@pytest.fixture
def projected(tmp_path: Path) -> Installation:
    inst = Installation(tmp_path, FULL)
    inst.setup(*FULL)
    write_topology(inst.config, dmz_split())
    topology.project(inst.config, inst.repo, dmz_split())
    return inst


# ─────────────────────────────────────────────────────────────────────────
# parsing
# ─────────────────────────────────────────────────────────────────────────


def test_the_allowlist_is_exactly_the_documented_verbs():
    assert set(node_shell.VERBS) == {
        "ping",
        "version",
        "status",
        "doctor",
        "compose-up",
        "compose-down",
        "compose-stop",
        "compose-restart",
        "compose-ps",
        "compose-pull",
        "compose-logs",
        "bundle-put",
        "checkout-put",
        "image-load",
        "hook",
    }


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        "ping; rm -rf /",
        "ping && id",
        "ping | sh",
        "compose-up $(id)",
        "compose-up `id`",
        "compose-up 'librechat'",
        'compose-up "librechat"',
        "compose-logs ../../etc/passwd",
        "compose-logs /etc/passwd",
        "hook ~root",
        "compose-up librechat\nid",
        "compose-up -d",
        "compose-up --volumes",
        "compose-logs --tail=1;id",
        "x" * 3000,
        " ".join(["ping"] * 30),
        "ping\x00",
    ],
)
def test_anything_but_plain_words_is_refused(raw):
    with pytest.raises(Refused):
        node_shell.parse_command(raw)


def test_plain_words_and_declared_options_pass():
    assert node_shell.parse_command("compose-logs librechat --tail=50") == [
        "compose-logs",
        "librechat",
        "--tail=50",
    ]


def test_random_input_never_yields_a_word_outside_the_character_set():
    rng = random.Random(20261030)
    alphabet = "abcz09-_.:=,+/\\$`'\";&|<>(){}[]*?~!#% \t\n\x00é"
    for _ in range(5000):
        raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        try:
            words = node_shell.parse_command(raw)
        except Refused:
            continue
        for word in words:
            assert not set(word) & set("/\\$`'\";&|<>(){}[]*?~!#% \t\n\x00é"), word


# ─────────────────────────────────────────────────────────────────────────
# dispatch and audit
# ─────────────────────────────────────────────────────────────────────────


def test_an_unknown_verb_is_refused_and_audited(tmp_path: Path, capsys):
    ctx = remote_node(tmp_path)
    assert run(ctx, "shell") == 2
    assert "unknown verb 'shell'" in capsys.readouterr().err
    line = ctx.audit_log.read_text(encoding="utf-8")
    assert "verb=shell" in line and "rc=2" in line
    assert stat.S_IMODE(ctx.audit_log.stat().st_mode) == 0o600
    assert ctx.run.calls == []


def test_no_command_at_all_is_refused(tmp_path: Path, capsys):
    ctx = remote_node(tmp_path)
    assert node_shell.execute(ctx, None) == 2
    assert "only runs papaia node commands" in capsys.readouterr().err


def test_a_node_without_its_identity_file_refuses(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(Refused, match="node-name"):
        node_shell.context_from_args(["--repo-root", str(root), f"--node-root={root}"])


def test_every_call_leaves_one_audit_line(tmp_path: Path):
    ctx = remote_node(tmp_path)
    run(ctx, "frobnicate")
    run(ctx, "ping x")
    lines = ctx.audit_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all(line.split()[1] == "node=edge" for line in lines)


# ─────────────────────────────────────────────────────────────────────────
# compose verbs
# ─────────────────────────────────────────────────────────────────────────


def controller_ctx(inst: Installation, name: str) -> Context:
    ctx = node_shell.context_from_args(
        ["--repo-root", str(inst.repo), f"--controller-config={inst.config}", f"--node={name}"]
    )
    ctx.run = Recorder()
    return ctx


def test_compose_up_runs_only_what_the_node_has(projected: Installation, monkeypatch):
    monkeypatch.setattr(node_shell, "_network_exists", lambda name: True)
    ctx = controller_ctx(projected, "edge")
    assert run(ctx, "compose-up keycloak link-gateway") == 0
    argv = ctx.run.calls[-1]
    assert argv[:2] == ["docker", "compose"]
    assert str(projected.repo / "src/infra/link-gateway/docker-compose.yml") in argv
    up = argv.index("up")
    assert argv[up : up + 2] == ["up", "-d"]
    assert set(argv[up + 2 :]) == {"keycloak", "keycloak-postgres", "link-gateway"}
    assert argv[argv.index("--env-file") + 1] == str(projected.repo / "src" / ".env")


def test_a_service_of_another_node_is_refused(projected: Installation, capsys):
    ctx = controller_ctx(projected, "edge")
    assert run(ctx, "compose-up librechat") == 2
    assert "'librechat' does not run on node 'edge'" in capsys.readouterr().err
    assert ctx.run.calls == []


def test_unexpected_options_are_refused(projected: Installation):
    ctx = controller_ctx(projected, "edge")
    assert run(ctx, "compose-up --force-recreate=1") == 2
    assert run(ctx, "compose-logs keycloak --tail=0") == 2
    assert run(ctx, "compose-logs keycloak --tail=99999") == 2
    assert run(ctx, "compose-ps keycloak") == 2
    assert ctx.run.calls == []


def test_compose_down_of_one_service_keeps_the_rest(projected: Installation, monkeypatch):
    monkeypatch.setattr(node_shell, "_network_exists", lambda name: True)
    ctx = controller_ctx(projected, "edge")
    run(ctx, "compose-down litellm")
    assert ctx.run.calls[-1][-6:-3] == ["rm", "--stop", "--force"]
    run(ctx, "compose-down")
    assert ctx.run.calls[-1][-1] == "down"


def test_materialize_brings_the_bundle_env_files_into_the_checkout(projected: Installation):
    ctx = controller_ctx(projected, "internal")
    stale = projected.repo / "src" / "infra" / "keycloak" / ".env"
    stale.write_text("KC_ADMIN_PASSWORD=from-another-node\n", encoding="utf-8")
    node_shell.materialize(ctx)
    root_env = (projected.repo / "src" / ".env").read_text(encoding="utf-8")
    assert "PAPAIA_NODE=internal" in root_env
    assert not stale.exists(), "a service that moved away leaves no .env behind"
    runtime = ctx.bundle / "overrides" / node_shell.RUNTIME_OVERRIDE
    assert json.loads(runtime.read_text())["services"]["link-gateway"]["user"] == (
        f"{os.getuid()}:{os.getgid()}"
    )


def test_an_addon_override_waits_for_its_network(projected: Installation, monkeypatch):
    overrides = topology.bundle_dir(projected.config, "internal") / "overrides"
    (overrides / "docker-compose.docs.override.yml").write_text(
        "services:\n  librechat:\n    networks: [docs-net]\nnetworks:\n  docs-net:\n"
        "    external: true\n",
        encoding="utf-8",
    )
    ctx = controller_ctx(projected, "internal")
    monkeypatch.setattr(node_shell, "_network_exists", lambda name: False)
    assert not any("docs.override" in f for f in node_shell.compose_files(ctx))
    monkeypatch.setattr(node_shell, "_network_exists", lambda name: True)
    assert any("docs.override" in f for f in node_shell.compose_files(ctx))


# ─────────────────────────────────────────────────────────────────────────
# hooks
# ─────────────────────────────────────────────────────────────────────────


def test_a_hook_runs_where_its_service_runs(projected: Installation):
    ctx = controller_ctx(projected, "edge")
    assert run(ctx, "hook keycloak-role-sync") == 0
    argv = ctx.run.calls[-1]
    assert argv[1:3] == ["-m", "lib.cli"] and argv[-1] == "keycloak-role-sync"
    assert argv[argv.index("--config-dir") + 1] == str(projected.config)


def test_a_hook_for_a_service_elsewhere_is_refused(projected: Installation):
    ctx = controller_ctx(projected, "internal")
    assert run(ctx, "hook npm-provision") == 2
    assert run(ctx, "hook rm-rf") == 2
    assert ctx.run.calls == []


# ─────────────────────────────────────────────────────────────────────────
# uploads
# ─────────────────────────────────────────────────────────────────────────


def bundle_tar(node: str = "edge", extra=()) -> bytes:
    manifest = json.dumps(
        {
            "node": node,
            "services": ["keycloak"],
            "profiles": ["keycloak"],
            "state_dirs": ["infra/nginx/nginx-data"],
        }
    ).encode()
    return tar_bytes(
        [
            ("node.json", manifest, 0o644),
            (".env", b"COMPOSE_PROFILES=keycloak\n", 0o600),
            ("infra/keycloak/keycloak.conf", b"x=1\n", 0o644),
            *extra,
        ]
    )


def test_a_bundle_is_installed_with_its_modes(tmp_path: Path):
    ctx = remote_node(tmp_path)
    assert run(ctx, "bundle-put", bundle_tar()) == 0
    config = ctx.config_dir
    assert (config / "infra/keycloak/keycloak.conf").read_text() == "x=1\n"
    assert stat.S_IMODE((config / ".env").stat().st_mode) == 0o600
    assert stat.S_IMODE((config / "infra/keycloak/keycloak.conf").stat().st_mode) == 0o644
    assert (config / "infra/nginx/nginx-data").is_dir()


def test_a_new_bundle_removes_what_the_old_one_had(tmp_path: Path):
    ctx = remote_node(tmp_path)
    run(ctx, "bundle-put", bundle_tar(extra=[("ai/litellm/config.yaml", b"a\n", 0o644)]))
    assert (ctx.config_dir / "ai/litellm/config.yaml").is_file()
    (ctx.config_dir / "infra/nginx/nginx-data/database.sqlite").write_text("state")
    run(ctx, "bundle-put", bundle_tar())
    assert not (ctx.config_dir / "ai/litellm/config.yaml").exists()
    # State the bundle never shipped is never touched.
    assert (ctx.config_dir / "infra/nginx/nginx-data/database.sqlite").read_text() == "state"


def test_a_bundle_for_another_node_is_refused(tmp_path: Path, capsys):
    ctx = remote_node(tmp_path)
    assert run(ctx, "bundle-put", bundle_tar(node="internal")) == 2
    assert "for node 'internal'" in capsys.readouterr().err
    assert not (ctx.config_dir / ".env").exists()


@pytest.mark.parametrize(
    "entries, kind, fragment",
    [
        ([("../evil", b"x", 0o644)], tarfile.REGTYPE, "outside the target"),
        ([("a/../../evil", b"x", 0o644)], tarfile.REGTYPE, "outside the target"),
        ([("/etc/cron.d/evil", b"x", 0o644)], tarfile.REGTYPE, "absolute"),
        ([("link", b"", 0o777)], tarfile.SYMTYPE, "not a plain file"),
        ([("hard", b"", 0o644)], tarfile.LNKTYPE, "not a plain file"),
        ([("dev", b"", 0o644)], tarfile.CHRTYPE, "not a plain file"),
        ([("fifo", b"", 0o644)], tarfile.FIFOTYPE, "not a plain file"),
    ],
)
def test_unsafe_archive_members_are_refused_before_anything_is_written(
    tmp_path: Path, capsys, entries, kind, fragment
):
    ctx = remote_node(tmp_path)
    assert run(ctx, "bundle-put", tar_bytes(entries, kind=kind)) == 2
    assert fragment in capsys.readouterr().err
    assert list(ctx.config_dir.iterdir()) == []
    assert not (tmp_path / "evil").exists()


def test_an_oversized_upload_is_refused(tmp_path: Path, monkeypatch, capsys):
    ctx = remote_node(tmp_path)
    monkeypatch.setattr(node_shell, "BUNDLE_LIMIT", 1024)
    assert run(ctx, "bundle-put", os.urandom(4096)) == 2
    assert "larger than" in capsys.readouterr().err


def test_an_archive_that_expands_too_far_is_refused(tmp_path: Path, monkeypatch, capsys):
    ctx = remote_node(tmp_path)
    monkeypatch.setattr(node_shell, "BUNDLE_LIMIT", 2048)
    archive = tar_bytes([("zeros", b"\0" * 64 * 1024, 0o644)])
    assert len(archive) < 2048
    assert run(ctx, "bundle-put", archive) == 2
    assert "expands beyond" in capsys.readouterr().err


def test_garbage_is_not_an_archive(tmp_path: Path, capsys):
    ctx = remote_node(tmp_path)
    assert run(ctx, "bundle-put", b"definitely not a tar file") == 2
    assert "not a tar archive" in capsys.readouterr().err


def test_the_controller_never_accepts_uploads(projected: Installation):
    ctx = controller_ctx(projected, "internal")
    assert run(ctx, "bundle-put", bundle_tar("internal")) == 2
    assert run(ctx, "checkout-put 1.8.0", b"") == 2


def checkout_tar(marker: str = "1") -> bytes:
    return tar_bytes(
        [
            ("tools/papaia-ctl", b"#!/usr/bin/env bash\n", 0o755),
            ("src/docker-compose.yml", f"# {marker}\n".encode(), 0o644),
        ]
    )


def test_a_release_is_installed_and_the_checkout_points_at_it(tmp_path: Path):
    ctx = remote_node(tmp_path)
    assert run(ctx, "checkout-put 1.8.0", checkout_tar()) == 0
    assert os.readlink(ctx.checkout) == "releases/1.8.0"
    assert (ctx.checkout / "tools/papaia-ctl").stat().st_mode & 0o100
    assert run(ctx, "checkout-put 1.9.0", checkout_tar("2")) == 0
    assert os.readlink(ctx.checkout) == "releases/1.9.0"
    assert (ctx.checkout / "src/docker-compose.yml").read_text() == "# 2\n"


def test_old_releases_are_pruned(tmp_path: Path):
    ctx = remote_node(tmp_path)
    for version in ("1.6.0", "1.7.0", "1.8.0", "1.9.0"):
        run(ctx, f"checkout-put {version}", checkout_tar(version))
    left = sorted(p.name for p in ctx.releases.iterdir() if not p.name.startswith("."))
    assert left == ["1.8.0", "1.9.0"]


@pytest.mark.parametrize("command", ["checkout-put", "checkout-put ../x", "checkout-put a b"])
def test_checkout_put_needs_a_version(tmp_path: Path, command: str):
    assert run(remote_node(tmp_path), command, checkout_tar()) == 2


def test_an_archive_that_is_not_a_checkout_is_refused(tmp_path: Path, capsys):
    ctx = remote_node(tmp_path)
    assert run(ctx, "checkout-put 1.8.0", tar_bytes([("README", b"x", 0o644)])) == 2
    assert "not a papAIa checkout" in capsys.readouterr().err
    assert not ctx.checkout.exists()


# ─────────────────────────────────────────────────────────────────────────
# end to end: the real bundle of a projected installation
# ─────────────────────────────────────────────────────────────────────────


def test_the_projected_bundle_installs_on_the_node(projected: Installation, tmp_path: Path):
    ctx = remote_node(tmp_path / "edge-host", checkout=projected.repo)
    archive = nodes.bundle_archive(projected.config, "edge")
    assert run(ctx, "bundle-put", archive) == 0
    installed = {
        p.relative_to(ctx.config_dir).as_posix() for p in ctx.config_dir.rglob("*") if p.is_file()
    }
    assert {
        "node.json",
        ".env",
        "infra/keycloak/.env",
        "link/haproxy.cfg",
        "link/node.key",
        "deployment.yaml",
    } <= installed
    assert "link-ca/ca.key" not in installed
    assert not any(name.endswith("id_ed25519") for name in installed)
    assert stat.S_IMODE((ctx.config_dir / "link/node.key").stat().st_mode) == 0o600
    assert run(ctx, "ping") == 0
