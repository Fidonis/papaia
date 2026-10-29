"""Golden tests: what a single-node installation produces, pinned byte for byte.

The multi-node work (topology, node bundles, the link gateway, per-node backup and
upgrade) adds code paths next to the single-node ones. An existing installation must not
notice any of it: the same `setup` writes the same files, `deployment.yaml` keeps its
shape, `status --json` and `doctor --json` read the same and a backup manifest lists the
same artifacts. These tests pin that output for a few fixture deployments, so a change
that leaks into the single-node path fails here instead of on a customer host.

Each fixture runs `setup` against a copy of this checkout's `src/` in a temporary
directory. What legitimately differs between two runs or two machines is normalised
before the digest is taken: generated secrets, the temporary paths, the IDs of the user
running the test and timestamps. Everything else is compared exactly.

When a change to the single-node output is intended, regenerate the snapshot and review
the diff of `golden/single-node.json` like any other change:

    PAPAIA_UPDATE_GOLDEN=1 pytest tests/test_golden_single_node.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from stack_helpers import FakeDocker, ps_line

from lib import backup, cli, common, defaults, deployment, doctor, envtree, smtp, status
from lib.doctor import MemInfo, Probes

REPO = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).parent / "golden" / "single-node.json"
UPDATE = os.environ.get("PAPAIA_UPDATE_GOLDEN") == "1"

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
GIB = 1024**3

# What `setup` reads from the checkout. Copied from the working tree, not from git, so
# an uncommitted change to a compose fragment or a template is what gets tested.
_CHECKOUT_FILES = ("tools/deployment.template.yaml", "VERSION", "ADDON_API", "CHANGELOG.md")
_IGNORED = shutil.ignore_patterns(
    ".env", "papaia-realm.json", "__pycache__", ".pytest_cache", "*.pyc", "*.tmp"
)

# One deployment per shape an operator commonly picks. The flags are the ones the bash
# wizard hands to `lib.cli setup` after it has asked its questions.
FIXTURES: dict[str, list[str]] = {
    "default": ["--app-host=https://papaia.example.org"],
    "full": [
        "--app-host=https://papaia.example.org",
        # The derived auth host: `setup` re-derives it on a run without flags.
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
        "--smtp-from-name=papAIa",
    ],
    "external-oidc": [
        "--app-host=https://papaia.example.org",
        "--auth-provider=external_oidc",
        "--oidc-issuer=https://login.example.org/realms/corp",
        "--reverse-proxy-provider=external_proxy",
        "--enable-local-ai=false",
        "--enable-manager=false",
    ],
}

# Keys of the root .env that describe the machine and the user running the test.
_HOST_KEYS = ("UID", "GID", "DOCKER_GID")


# ─────────────────────────────────────────────────────────────────────────
# building an installation
# ─────────────────────────────────────────────────────────────────────────


def _checkout(tmp_path: Path) -> Path:
    """A copy of what `setup` reads, under `<tmp>/workspace/papaia` so the workspace
    and backup paths it derives from the checkout's name are the real ones."""
    dest = tmp_path / "workspace" / "papaia"
    shutil.copytree(REPO / "src", dest / "src", ignore=_IGNORED)
    for rel in _CHECKOUT_FILES:
        source = REPO / rel
        if source.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest / rel)
    return dest


def _cli(repo: Path, config: Path, *args: str) -> None:
    code = cli.main(["--repo-root", str(repo), "--config-dir", str(config), *args])
    assert code == 0, f"lib.cli {' '.join(args)} exited {code}"


class Installation:
    def __init__(self, tmp_path: Path, flags: list[str]):
        self.repo = _checkout(tmp_path)
        self.workspace = self.repo.parent
        self.config = self.workspace / "papaia-config"
        self.flags = flags

    def setup(self, *flags: str) -> None:
        _cli(self.repo, self.config, "setup", "--env=papaia", *flags)

    def secrets(self) -> list[str]:
        """Every generated secret of this installation, longest first so that no
        secret is replaced inside a longer one."""
        seed = envtree.load_seed_tree(self.repo)
        tree = envtree.load_config_dir_tree(self.config, self.repo)
        found: set[str] = set()
        for rel_dir, values in seed.items():
            for key, seed_value in values.items():
                if common.marks_generated_secret(seed_value):
                    value = tree.get(rel_dir, {}).get(key, "")
                    if value and not common.is_placeholder(value):
                        found.add(value)
        return sorted(found, key=len, reverse=True)

    def normalise(self, text: str) -> str:
        for secret in self.secrets():
            text = text.replace(secret, "<SECRET>")
        # Longest path first: the config dir and the checkout sit inside the workspace.
        for path, label in (
            (self.config, "<CONFIG>"),
            (self.repo, "<REPO>"),
            (self.workspace, "<WORKSPACE>"),
        ):
            text = text.replace(str(path), label)
        lines = []
        for line in text.split("\n"):
            key = line.partition("=")[0]
            if key in _HOST_KEYS and "=" in line:
                line = f"{key}=<HOST>"
            lines.append(line)
        return "\n".join(lines)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _tree_digests(inst: Installation) -> dict[str, str]:
    """sha256 of every file under the config directory, normalised."""
    digests: dict[str, str] = {}
    for path in sorted(p for p in inst.config.rglob("*") if p.is_file()):
        rel = path.relative_to(inst.config).as_posix()
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            digests[rel] = hashlib.sha256(raw).hexdigest()
            continue
        if rel == "deployed.lock":
            summary = json.loads(text)
            summary["deployed_at"] = "<TIME>"
            text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        digests[rel] = _digest(inst.normalise(text))
    return digests


def _ps_lines(inst: Installation) -> list[str]:
    """`docker ps` as a healthy installation answers it: one running container per
    declared service of the active profiles."""
    active = status.active_profiles(inst.config)
    project = status.compose_project(inst.config)
    lines = []
    for item in status.core_inventory(inst.repo, active):
        lines.append(
            ps_line(
                f"{project}-{item.service}-1",
                "running",
                "Up 2 hours (healthy)",
                item.service,
                f"papaia-{item.module}" if item.module != status.UNGROUPED_MODULE else "",
                item.role,
                project=project,
            )
        )
    return lines


def _probes() -> Probes:
    return Probes(
        disk_usage=lambda path: (500 * GIB, 400 * GIB),
        connect=lambda host, port: False,
        resolve=lambda host: doctor.RESOLVED,
        cert_enddate=lambda path, run: NOW + timedelta(days=365),
        meminfo=lambda: MemInfo(16 * GIB, 12 * GIB, 0, 0),
        loadavg=lambda: (0.3, 0.2, 0.1),
        cpu_count=lambda: 8,
        in_container=lambda: False,
        kernel_clock_synchronized=lambda: True,
        smtp_probe=lambda *args: smtp.ProbeResult(True, "ok", login="ok"),
        dev_root=Path("/papaia-test-has-no-devices"),
    )


def _status_json(inst: Installation) -> str:
    report = status.collect(
        inst.config,
        inst.repo,
        include_addons=True,
        run=FakeDocker(_ps_lines(inst)),
        now=NOW,
    )
    return inst.normalise(status.to_json(report))


def _doctor_json(inst: Installation) -> str:
    report = doctor.run_checks(
        inst.config,
        inst.repo,
        run=FakeDocker(_ps_lines(inst)),
        probes=_probes(),
        now=NOW,
    )
    return inst.normalise(doctor.to_json(report))


def _backup_manifest(inst: Installation) -> str:
    """The manifest `backup` writes when every archive succeeds. `created_at` is the
    wall clock of the run and is blanked."""
    project = status.compose_project(inst.config)
    existing = [(project, f"{project}_{key}") for key in backup.resolve_core_volumes(inst.repo)]
    plan = backup.build_plan(
        inst.config,
        inst.repo,
        inst.workspace / "backup",
        existing=existing,
        now=datetime(2026, 10, 1, 14, 0, 0),
    )
    common.ensure_dir(plan.snapshot)
    results = {artifact.archive: "ok" for artifact in plan.artifacts}
    manifest = backup.write_manifest(plan.snapshot, plan, results, papaia_version="1.0.0")
    manifest["created_at"] = "<TIME>"
    return inst.normalise(yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False))


def _defaults(inst: Installation) -> str:
    """The values the wizard pre-fills its questions from. A key appearing here for an
    existing installation is a question a repeated `setup` would newly ask."""
    values = defaults.compute_defaults(inst.config, inst.repo)
    return inst.normalise("".join(f"{key}={value}\n" for key, value in values.items()))


def _compose_version() -> str | None:
    try:
        done = subprocess.run(
            ["docker", "compose", "version", "--short"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else None


def _compose_config(inst: Installation) -> str | None:
    """`docker compose config` of the core project as `start` assembles it, or None
    without a Docker CLI. The overrides are the ones `start` passes with `-f`."""
    envtree.materialize_core_env(inst.config, inst.repo)
    files = ["-f", str(inst.repo / "src" / "docker-compose.yml")]
    for override in sorted((inst.config / "overrides").glob("docker-compose.*.override.yml")):
        files += ["-f", str(override)]
    try:
        done = subprocess.run(
            [
                "docker",
                "compose",
                *files,
                "--env-file",
                str(inst.repo / "src" / ".env"),
                "config",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        pytest.fail(f"docker compose config failed:\n{done.stderr}")
    return inst.normalise(done.stdout)


# ─────────────────────────────────────────────────────────────────────────
# snapshot
# ─────────────────────────────────────────────────────────────────────────


def _snapshot(tmp_path: Path, name: str) -> dict:
    inst = Installation(tmp_path, FIXTURES[name])
    inst.setup(*inst.flags)
    first_tree = _tree_digests(inst)
    first_manifest = (inst.config / "deployment.yaml").read_text(encoding="utf-8")

    # A repeated `setup` without flags: what a bare re-run and `setup --env-only` hand
    # to the Python side. What it changes is pinned as well; on the `full` fixture that
    # is the profile order in `.env` and `deployment.yaml`, which predates this test.
    inst.setup()
    repeated_tree = _tree_digests(inst)

    # The Python half of `upgrade` on an unchanged release: new keys, a re-render
    # without flags, and the render `start` does before it brings the stack up.
    _cli(inst.repo, inst.config, "sync-env")
    inst.setup()
    _cli(inst.repo, inst.config, "render")
    upgraded_manifest = (inst.config / "deployment.yaml").read_text(encoding="utf-8")

    return {
        "tree": first_tree,
        "repeated_setup_changes": sorted(
            rel for rel in set(first_tree) | set(repeated_tree)
            if first_tree.get(rel) != repeated_tree.get(rel)
        ),
        "deployment_yaml": inst.normalise(first_manifest),
        "deployment_yaml_after_upgrade": inst.normalise(upgraded_manifest),
        "defaults": _defaults(inst),
        "status_json": _digest(_status_json(inst)),
        "doctor_json": _digest(_doctor_json(inst)),
        "backup_manifest": _digest(_backup_manifest(inst)),
        "compose": {"version": _compose_version(), "config": _maybe_digest(_compose_config(inst))},
    }


def _maybe_digest(text: str | None) -> str | None:
    return None if text is None else _digest(text)


def _load_golden() -> dict:
    if not GOLDEN.is_file():
        return {}
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def _save_golden(data: dict) -> None:
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_single_node_output_matches_the_golden_snapshot(tmp_path: Path, name: str) -> None:
    actual = _snapshot(tmp_path, name)
    golden = _load_golden()

    if UPDATE:
        golden[name] = actual
        _save_golden(golden)
        return

    assert name in golden, f"no golden snapshot for {name!r}; run with PAPAIA_UPDATE_GOLDEN=1"
    expected = golden[name]

    changed = sorted(
        rel for rel in set(expected["tree"]) | set(actual["tree"])
        if expected["tree"].get(rel) != actual["tree"].get(rel)
    )
    assert not changed, f"{name}: rendered config tree differs in {changed}"
    for key in (
        "repeated_setup_changes",
        "deployment_yaml",
        "deployment_yaml_after_upgrade",
        "defaults",
        "status_json",
        "doctor_json",
        "backup_manifest",
    ):
        assert actual[key] == expected[key], f"{name}: {key} differs from the golden snapshot"

    # The compose output depends on the Compose release that renders it, so it is only
    # compared on the release the snapshot was taken with.
    recorded, rendered = expected["compose"], actual["compose"]
    if rendered["config"] is not None and rendered["version"] == recorded["version"]:
        assert rendered["config"] == recorded["config"], (
            f"{name}: docker compose config differs from the golden snapshot"
        )


def test_single_node_deployment_yaml_carries_no_topology(tmp_path: Path) -> None:
    inst = Installation(tmp_path, FIXTURES["full"])
    inst.setup(*inst.flags)
    inst.setup()
    assert "topology" not in deployment.load(inst.config)
