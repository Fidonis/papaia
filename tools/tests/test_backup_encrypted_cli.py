"""`papaia-ctl backup` end to end in bash, with `docker` replaced by a function that runs
the same `tar` on host directories. `py_cli` is the real one.

Checked on what lands at the target: every archive is an age file, the canaries are only
readable with a recipient's key, no key material is in any archive (rollback keys, an
age identity, the revocation-list and delegation key volumes), and a wrong target is
refused before Docker is called at all.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

from lib import age, backup, backup_crypt

TOOLS = Path(__file__).resolve().parents[1]
BACKUP_SH = TOOLS / "lib" / "sh" / "backup.sh"
BASH = shutil.which("bash")
TAR = shutil.which("tar")

pytestmark = pytest.mark.skipif(BASH is None or TAR is None, reason="bash or tar missing")

_HARNESS = r"""
set -euo pipefail
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
py_cli() {
    PYTHONPATH="@TOOLS@" "@PYTHON@" -m lib.cli --repo-root "$REPO_ROOT" \
        --config-dir "$CONFIG_DIR" "$@"
}
# A docker that knows `volume ls`, `ps` and `run ... tar czf - ... -C <mount> .`; a named
# volume is the directory @VOLUMES@/<name>.
docker() {
    echo "docker $*" >> "@LOG@"
    case "$1" in
        volume) cat "@VOLUME_LIST@" ;;
        ps|inspect|pause|unpause) ;;
        run)
            shift
            local -a cmd=()
            local src="" dst="" image_seen=0
            while [ $# -gt 0 ]; do
                case "$1" in
                    --rm) ;;
                    -v) src="${2%%:*}"; shift ;;
                    *)
                        if [ "$image_seen" -eq 0 ]; then image_seen=1; else cmd+=("$1"); fi
                        ;;
                esac
                shift
            done
            case "$src" in
                /*) : ;;
                *) src="@VOLUMES@/$src" ;;
            esac
            local -a out=()
            local arg
            for arg in "${cmd[@]}"; do
                case "$arg" in
                    /src|/volume) out+=("$src") ;;
                    *) out+=("$arg") ;;
                esac
            done
            "@TAR@" "${out[@]:1}"
            ;;
    esac
}
source "@BACKUP@"
_require_setup_done() { :; }
_topology_mode() { echo single; }
"""

AGE_KEY_TEXT = "# rollback key\n" + "AGE-SECRET-KEY-1" + "Q" * 58 + "\n"


def _stack(tmp_path: Path) -> dict:
    repo = tmp_path / "repo"
    (repo / "src" / "infra").mkdir(parents=True)
    (repo / "src" / "docker-compose.yml").write_text(
        "include:\n  - path: ./infra/docker-compose.yml\n", encoding="utf-8"
    )
    (repo / "src" / "infra" / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: stub\n"
        "volumes:\n  keycloak-postgresql:\n  papaia-lifecycle-key:\n  papaia-erasure:\n",
        encoding="utf-8",
    )
    addon = tmp_path / "addons" / "flow"
    addon.mkdir(parents=True)
    (addon / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: stub\nvolumes:\n  flow-db:\n  flow-delegation-key:\n",
        encoding="utf-8",
    )
    (addon / "papaia-app.yaml").write_text("name: flow\n", encoding="utf-8")
    config = tmp_path / "papaia-config"
    (config / "state" / "rollback").mkdir(parents=True)
    (config / "state" / "rollback" / "up-1.key").write_text(AGE_KEY_TEXT, encoding="utf-8")
    (config / "ai" / "litellm").mkdir(parents=True)
    (config / "ai" / "litellm" / "test-hosted.env").write_text("TEST_HOSTED_API_KEY=k\n")
    (config / "notes.txt").write_text("canary-config-5521\n", encoding="utf-8")
    (config / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
    (config / "deployment.yaml").write_text(
        yaml.safe_dump({"addons": [{"name": "flow", "path": str(addon), "active": True}]}),
        encoding="utf-8",
    )
    volumes = tmp_path / "volumes"
    for name, content in {
        "papaia_keycloak-postgresql": "canary-db-7731",
        "papaia_papaia-lifecycle-key": "canary-key-revocation-91",
        "papaia_papaia-erasure": "canary-key-journal-93",
        "flow_flow-db": "canary-flow-4410",
        "flow_flow-delegation-key": "canary-key-delegation-92",
    }.items():
        (volumes / name).mkdir(parents=True)
        (volumes / name / "data").write_text(content, encoding="utf-8")
    volume_list = tmp_path / "volume-list.tsv"
    volume_list.write_text(
        "".join(
            f"{name.split('_', 1)[0]}\t{name}\n"
            for name in sorted(p.name for p in volumes.iterdir())
        ),
        encoding="utf-8",
    )
    target = tmp_path / "backup"
    target.mkdir()
    return {"repo": repo, "config": config, "volumes": volumes, "list": volume_list,
            "target": target}


def _run(tmp_path: Path, stack: dict, body: str) -> tuple[subprocess.CompletedProcess, str]:
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    harness = (
        _HARNESS.replace("@CONFIG@", stack["config"].as_posix())
        .replace("@ROOT@", stack["repo"].as_posix())
        .replace("@TOOLS@", TOOLS.as_posix())
        .replace("@PYTHON@", sys.executable)
        .replace("@LOG@", log.as_posix())
        .replace("@VOLUME_LIST@", stack["list"].as_posix())
        .replace("@VOLUMES@", stack["volumes"].as_posix())
        .replace("@TAR@", str(TAR))
        .replace("@BACKUP@", BACKUP_SH.as_posix())
    )
    done = subprocess.run(
        [str(BASH), "-c", f"{harness}\n{body}"], capture_output=True, text=True, check=False
    )
    return done, log.read_text(encoding="utf-8")


def _members(path: Path, identity: str) -> dict[str, bytes]:
    plain = io.BytesIO()
    with open(path, "rb") as handle:
        age.decrypt(handle, plain, [identity])
    plain.seek(0)
    with tarfile.open(fileobj=plain, mode="r:gz") as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


def test_backup_writes_only_sealed_archives_without_key_material(tmp_path: Path):
    stack = _stack(tmp_path)
    (operations, operations_r), (emergency, emergency_r) = (
        age.generate_identity(), age.generate_identity()
    )
    backup_crypt.add_recipient(stack["config"], "betrieb", operations_r)
    backup_crypt.add_recipient(stack["config"], "notfall", emergency_r)
    backup_crypt.init_target(stack["config"], stack["target"])

    done, calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}" --keep=7')
    assert done.returncode == 0, done.stderr + done.stdout
    assert "backup complete" in done.stdout

    entry = backup.load_index(stack["target"])["backups"][0]
    snapshot = stack["target"] / entry["id"]
    manifest = backup.read_manifest(snapshot)
    archives = [snapshot / a["archive"] for a in manifest["artifacts"]]
    assert {a["target"] for a in manifest["artifacts"] if a["kind"] == "volume"} == {
        "papaia_keycloak-postgresql", "flow_flow-db",
    }
    assert {e["volume"] for e in manifest["excluded"]} == {
        "papaia_papaia-lifecycle-key", "papaia_papaia-erasure", "flow_flow-delegation-key",
    }
    # The key volumes never reached tar.
    assert "lifecycle-key" not in calls and "delegation-key" not in calls and "erasure" not in calls

    # The scan: nothing at the target holds a canary or a key in clear ...
    every_file = [p for p in stack["target"].rglob("*") if p.is_file()]
    for path in every_file:
        raw = path.read_bytes()
        for needle in (b"canary-", b"AGE-SECRET-KEY-", b"TEST_HOSTED"):
            assert needle not in raw, (path, needle)
    # ... and decrypted with either key, the archives hold the canaries and no key material.
    for identity in (operations, emergency):
        opened: dict[str, bytes] = {}
        for path in archives:
            assert path.name.endswith(".tar.gz.age")
            opened.update({f"{path.name}:{k}": v for k, v in _members(path, identity).items()})
        blob = b"".join(opened.values())
        assert b"canary-config-5521" in blob and b"canary-db-7731" in blob
        assert b"canary-flow-4410" in blob
        assert b"AGE-SECRET-KEY-" not in blob and b"canary-key-" not in blob
        assert not any("state/rollback" in name or "test-hosted" in name for name in opened)
    assert all(len(a["sha256"]) == 64 for a in manifest["artifacts"])
    assert [r["name"] for r in manifest["encryption"]["recipients"]] == ["betrieb", "notfall"]


def test_an_age_key_outside_the_excluded_paths_fails_the_archive(tmp_path: Path):
    stack = _stack(tmp_path)
    (stack["config"] / "copied-key.txt").write_text(AGE_KEY_TEXT, encoding="utf-8")
    _identity, recipient = age.generate_identity()
    backup_crypt.add_recipient(stack["config"], "betrieb", recipient)
    backup_crypt.init_target(stack["config"], stack["target"])

    done, _calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}"')
    assert done.returncode == 0, done.stderr
    assert "completed with errors" in done.stderr
    assert "private age key" in done.stderr
    entry = backup.load_index(stack["target"])["backups"][0]
    assert entry["result"] == "partial"
    snapshot = stack["target"] / entry["id"]
    assert not (snapshot / backup.CONFIG_ARCHIVE).exists()
    assert not list(snapshot.rglob("*.part"))


def test_a_wrong_target_is_refused_before_docker_runs(tmp_path: Path):
    stack = _stack(tmp_path)
    _identity, recipient = age.generate_identity()
    backup_crypt.add_recipient(stack["config"], "betrieb", recipient)
    other = tmp_path / "other-config"
    other.mkdir()
    backup_crypt.init_target(other, stack["target"])

    done, calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}"')
    assert done.returncode == 3
    assert "another installation" in done.stderr
    assert "docker run" not in calls
    assert [p.name for p in stack["target"].iterdir()] == [backup_crypt.TARGET_FILE]


def test_an_unmounted_target_is_not_created(tmp_path: Path):
    stack = _stack(tmp_path)
    _identity, recipient = age.generate_identity()
    backup_crypt.add_recipient(stack["config"], "betrieb", recipient)
    missing = tmp_path / "mnt" / "share"

    done, calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{missing}"')
    assert done.returncode == 3
    assert "not mounted" in done.stderr
    assert not missing.exists() and "docker run" not in calls


def test_backup_without_recipient_is_refused(tmp_path: Path):
    stack = _stack(tmp_path)
    backup_crypt.init_target(stack["config"], stack["target"])
    done, calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}"')
    assert done.returncode == 3
    assert "never written unencrypted" in done.stderr
    assert "docker run" not in calls


def test_backup_keep_must_be_a_count(tmp_path: Path):
    stack = _stack(tmp_path)
    done, _calls = _run(tmp_path, stack, "cmd_backup --keep=0")
    assert done.returncode == 2
    assert "--keep" in done.stderr


def _audit(config: Path) -> list[dict]:
    path = config / "audit" / "papaia-ctl.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def test_backup_with_keep_writes_one_audit_row_per_write_and_delete(tmp_path: Path):
    stack = _stack(tmp_path)
    identity, recipient = age.generate_identity()
    backup_crypt.add_recipient(stack["config"], "betrieb", recipient)
    backup_crypt.init_target(stack["config"], stack["target"])
    index = backup.load_index(stack["target"])
    for day in ("01", "02"):
        old = stack["target"] / f"2020-01-{day}_00-00-00"
        old.mkdir()
        index["backups"].append({"id": old.name, "path": str(old), "result": "ok",
                                 "created_at": f"2020-01-{day}T00:00:00Z"})
    backup.save_index(stack["target"], index)

    done, _calls = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}" --keep=1')
    assert done.returncode == 0, done.stderr + done.stdout

    rows = _audit(stack["config"])
    assert all(r["format"] == "papaia.audit/1" for r in rows)
    events = [r["event"] for r in rows]
    assert events == ["backup_recipient_added", "backup_target_confirmed", "backup_written",
                      "backup_deleted", "backup_deleted"]
    target_row = rows[1]
    assert target_row["operation"] == "backup-target" and target_row["effect"] == "write"
    written = rows[2]
    entry = backup.load_index(stack["target"])["backups"][-1]
    assert written["detail"]["id"] == entry["id"] and written["result"] == "allowed"
    assert written["detail"]["recipients"] == ["betrieb"]
    deleted = rows[3:]
    assert sorted(r["detail"]["id"] for r in deleted) == [
        "2020-01-01_00-00-00", "2020-01-02_00-00-00"
    ]
    assert all(r["effect"] == "delete" and r["detail"]["reason"] == "retention"
               for r in deleted)
    # One run, one correlation id across the separate py_cli calls of bash.
    assert len({r["correlation_id"] for r in rows[2:]}) == 1
    log = (stack["config"] / "audit" / "papaia-ctl.jsonl").read_text(encoding="utf-8")
    assert identity not in log and "AGE-SECRET-KEY" not in log.upper()


def test_a_failing_retention_is_reported(tmp_path: Path):
    stack = _stack(tmp_path)
    _identity, recipient = age.generate_identity()
    backup_crypt.add_recipient(stack["config"], "betrieb", recipient)
    backup_crypt.init_target(stack["config"], stack["target"])
    # backup-prune fails; what it says on stderr must reach the operator.
    body = (
        'eval "real_$(declare -f py_cli)"\n'
        'py_cli() { if [ "$1" = backup-prune ]; then echo "ERROR: prune-broke-1187" >&2;'
        ' return 1; fi; real_py_cli "$@"; }\n'
        f'cmd_backup --backup-dir="{stack["target"]}" --keep=1'
    )
    done, _calls = _run(tmp_path, stack, body)
    assert "prune-broke-1187" in done.stderr
