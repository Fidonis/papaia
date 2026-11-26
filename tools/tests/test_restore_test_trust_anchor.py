"""`restore` and `restore-scoped` with `--test-trust-anchor=FILE` on a pre-release core
(ADR 0030, amendment 2).

A release candidate carries a bill of materials of scope `test`, signed with a local test
key, and no release key. A restore checks images twice before anything runs again: the
images of the Keycloak profile (with the runner of the admin steps) before the pending
post-restore step, and the images of each add-on of a scoped restore before it starts.
These tests run the real restore of lib/sh/backup.sh through the real option gate of
lib/sh/trust.sh, with the real image check of lib/sh/lifecycle.sh and lib/images.py.
Only the registry is a fake one in memory, and `docker` the stub of
test_restore_journal_cli, which runs `tar` on host directories; Compose answers for the
core with the Keycloak service and its image, and the add-on lists its database image.

- With the option, both commands pass the image check, print the banner at the start and
  the end and write one `papaia.audit/1` row per check of the bill of materials.
- A release `VERSION` refuses the option before anything is read or written.
- Without the option the restore still stops with exit code 3 before Keycloak starts, and
  names the cause.
- A wrong key and a `delivery` bill of materials are refused.
- No environment variable and no entry of the configuration turns it on.

The release path is covered unchanged by the existing restore tests.
"""

from __future__ import annotations

import os
import pickle
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from test_images import (
    D1,
    D2,
    ENTRIES,
    KEYCLOAK,
    LIFECYCLE,
    POSTGRES,
    REPO,
    _bom,
    _image,
    _new_keypair,
    _sign_bytes,
    _signed_registry,
)

from lib import images, suite
from lib import prerelease_anchor as pre
from tests import test_restore_journal_cli as journal

PRE = "1.10.0-rc.1"
BOM_NAME = "suite-1.10.0.yaml"
TRUST_SH = REPO / "tools" / "lib" / "sh" / "trust.sh"
TESTS = Path(__file__).resolve().parent
D6 = "sha256:" + "6" * 64
MANAGER = "ghcr.io/fidonis/papaia-manager"
RUNNER = f"{MANAGER}:1.8.0@{D6}"
# The bundled Keycloak behind the bundled proxy: its admin steps run in the runner.
EDGE = "COMPOSE_PROFILES=keycloak,nginx\nREVERSE_PROXY_PROVIDER=internal_nginx\n"
CORRELATION = "0b5a4c84-6f0a-4f36-9a4e-0d0c5a7d1e11"

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None or journal.BASH is None or journal.TAR is None,
    reason="openssl, bash and tar are needed for a restore",
)

# `py_cli` of the harness with the in-memory registry: everything else is lib.cli.
_PY_CLI = r"""
import pickle, sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from lib import cli, images
with open(sys.argv[3], "rb") as handle:
    registry = pickle.load(handle)
images.Registry = lambda: registry
sys.exit(cli.main(sys.argv[4:]))
"""

# What the harness of test_restore_journal_cli replaces with no-ops runs for real here.
_STUBBED_CHECKS = (
    "_verify_addon_images() { :; }\n",
    "_post_restore_before_modules() {\n"
    '    echo "post-restore core" >> "@LOG@"\n'
    '    rm -f "$CONFIG_DIR/post-restore.pending"\n'
    '    POST_RESTORE_STATUS="ok"\n'
    "}\n",
)

_BODY = r"""
py_cli() {
    echo "py_cli $*" >> "@LOG@"
    "@PYTHON@" "@WRAPPER@" "@TOOLS@" "@TESTS@" "@REGISTRY@" \
        --repo-root "$REPO_ROOT" --config-dir "$CONFIG_DIR" "$@"
}
# Compose of the core: the Keycloak service with its image; `up` starts nothing.
eval "_docker_volumes_and_run() $(declare -f docker | sed 1d)"
docker() {
    if [ "$1" != compose ]; then _docker_volumes_and_run "$@"; return; fi
    echo "docker $*" >> "@LOG@"
    case " $* " in
        *" config --services "*) echo keycloak ;;
        *" config --images "*) echo "@KEYCLOAK_REF@" ;;
    esac
}
_addon_image_list() { echo "@ADDON_REF@" >> "$3"; }
# `start` as far as a whole restore needs it here: the pending step before any module.
cmd_start() {
    echo "start $*" >> "@LOG@"
    local insecure=0
    case " $* " in *" --insecure-images "*) insecure=1 ;; esac
    _post_restore_before_modules "$insecure"
}
_dispatch() {
    local cmd="$1"
    shift
    case "$cmd" in
        restore) cmd_restore "$@" ;;
        restore-scoped) cmd_restore_scoped "$@" ;;
        *) error "Unknown command: $cmd"; exit 2 ;;
    esac
}
"""


def _harness() -> str:
    text = journal._HARNESS
    for stub in _STUBBED_CHECKS:
        assert stub in text, "the restore harness changed; update this test"
        text = text.replace(stub, "")
    marker = 'source "@ADDON@"\n'
    assert marker in text
    return text.replace(marker, f'source "{LIFECYCLE.as_posix()}"\n'
                                f'source "{TRUST_SH.as_posix()}"\n{marker}')


@pytest.fixture
def candidate(tmp_path: Path) -> dict:
    """The restore stack of test_restore_journal_cli on a pre-release core without a
    release key, on the host admin path (so the runner is checked), with one backup."""
    stack = journal._stack(tmp_path)
    repo, config = stack["repo"], stack["config"]
    (repo / "VERSION").write_text(f"{PRE}\n", encoding="ascii")
    manager = repo / "src" / "manager" / "docker-compose.yml"
    manager.parent.mkdir(parents=True)
    manager.write_text(yaml.safe_dump(
        {"services": {"papaia-manager": {"image": RUNNER, "profiles": ["manager"]}}}), "utf-8")
    with (config / ".env").open("a", encoding="utf-8") as env:
        env.write(EDGE)
    keys = tmp_path / "anchor-keys"
    keys.mkdir()
    stack["test_key"] = _new_keypair(keys, "test-signing")
    stack["other_key"] = _new_keypair(keys, "other-signing")
    stack["anchor"] = keys / "test-anchor.pub"
    stack["anchor"].write_text(stack["test_key"][1], encoding="ascii")
    stack["wrong_anchor"] = keys / "other-anchor.pub"
    stack["wrong_anchor"].write_text(stack["other_key"][1], encoding="ascii")
    registry = _signed_registry(stack["test_key"], tmp_path)
    ref = images.parse_ref(RUNNER)
    registry.add_signature(ref.registry, ref.repository, D6, stack["test_key"][0], tmp_path)
    stack["registry"] = tmp_path / "registry.pickle"
    stack["registry"].write_bytes(pickle.dumps(registry))
    stack["wrapper"] = tmp_path / "py_cli.py"
    stack["wrapper"].write_text(_PY_CLI, encoding="utf-8")
    _write_bom(tmp_path, stack)
    done, _ = _run(tmp_path, stack, f'cmd_backup --backup-dir="{stack["target"]}"')
    assert done.returncode == 0, done.stderr + done.stdout
    return stack


def _write_bom(tmp_path: Path, stack: dict, *, scope: str = "test") -> None:
    """The candidate's bill of materials of `scope`, signed with the test key: Keycloak,
    the database and the runner of the admin steps."""
    private, pem = stack["test_key"]
    doc = _bom(pem, [*ENTRIES, _image(MANAGER, "1.8.0", D6)], scope=scope)
    path = stack["repo"] / "compat" / BOM_NAME
    path.parent.mkdir(exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    sig_dir = tmp_path / "sig"
    sig_dir.mkdir(exist_ok=True)
    Path(f"{path}.sig").write_text(_sign_bytes(private, path.read_bytes(), sig_dir), "ascii")


def _run(tmp_path: Path, stack: dict, body: str, *, env: dict | None = None):
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    script = (
        (_harness() + _BODY + body).replace("@CONFIG@", stack["config"].as_posix())
        .replace("@ROOT@", stack["repo"].as_posix())
        .replace("@TOOLS@", journal.TOOLS.as_posix())
        .replace("@TESTS@", TESTS.as_posix())
        .replace("@PYTHON@", sys.executable)
        .replace("@WRAPPER@", stack["wrapper"].as_posix())
        .replace("@REGISTRY@", stack["registry"].as_posix())
        .replace("@KEYCLOAK_REF@", f"{KEYCLOAK}:26.7.0@{D1}")
        .replace("@ADDON_REF@", f"{POSTGRES}:18.3@{D2}")
        .replace("@LOG@", log.as_posix())
        .replace("@VOLUME_LIST@", stack["list"].as_posix())
        .replace("@VOLUMES@", stack["volumes"].as_posix())
        .replace("@ADDONS@", stack["addons"].as_posix())
        .replace("@STUB@", stack["stub"].as_posix())
        .replace("@IN_USE@", (tmp_path / "in-use.tsv").as_posix())
        .replace("@TARDIR@", str(Path(journal.TAR).parent))
        .replace("@TAR@", str(journal.TAR))
        .replace("@ADDON@", journal.ADDON_SH.as_posix())
        .replace("@BACKUP@", journal.BACKUP_SH.as_posix())
    )
    environ = {k: v for k, v in os.environ.items() if k != "PAPAIA_CORRELATION_ID"}
    done = subprocess.run(
        [str(journal.BASH), "-c", script], capture_output=True, text=True, check=False,
        timeout=180, env={**environ, **(env or {})}, cwd=tmp_path,
    )
    return done, log.read_text(encoding="utf-8").splitlines()


def _restore(tmp_path: Path, stack: dict, command: str, *extra: str, env=None):
    args = [command, "-y", f"--identity={stack['key']}", f"--backup-dir={stack['target']}"]
    if command == "restore-scoped":
        args.append("--only=addon:flow")
    quoted = " ".join(f"'{a}'" for a in [*args, *extra])
    return _run(tmp_path, stack, f"_dispatch_with_test_anchor _dispatch {quoted}", env=env)


def _anchor_rows(config: Path) -> list[dict]:
    return [row for row in journal._audit(config) if row["event"] == pre.EVENT] \
        if (config / images.AUDIT_LOG).is_file() else []


def _verify_calls(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("py_cli image-verify")]


# ── positive ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("command,checks", [
    # The Keycloak profile with the runner before the pending post-restore step.
    ("restore", 1),
    # The same, then the images of the restored add-on before it starts.
    ("restore-scoped", 2),
])
def test_restore_passes_the_image_check_with_the_anchor(tmp_path, candidate, command, checks):
    stack = candidate
    journal._after_backup(stack)

    done, calls = _restore(tmp_path, stack, command, f"--test-trust-anchor={stack['anchor']}")

    output = done.stdout + done.stderr
    assert done.returncode == 0, output
    # The restore point is back and the pending step ran after the check.
    assert (stack["volumes"] / "flow_flow-db" / "run-1").read_text() == "canary-flow-4410"
    assert "post-restore core now" in calls
    assert not (stack["config"] / "post-restore.pending").exists()
    # The banner opens and closes the command.
    assert (f"TEST TRUST ANCHOR: --test-trust-anchor is set for this '{command}' only."
            in done.stderr)
    assert f"TEST TRUST ANCHOR: '{command}' ended with exit code 0." in done.stderr
    assert "NOT FOR PRODUCTION" in done.stderr
    # Every image check got the anchor and the one correlation id of the command.
    verify = _verify_calls(calls)
    assert len(verify) == checks
    for call in verify:
        assert f"--test-trust-anchor={stack['anchor']}" in call
        assert "--command=restore" in call
    assert "--images-file=" in verify[0]
    if command == "restore-scoped":
        assert "--addon-images=flow=" in verify[1]
    # One row per check of the bill of materials, under that correlation id.
    rows = _anchor_rows(stack["config"])
    assert [(row["operation"], row["result"]) for row in rows] == [("restore", "allowed")] * checks
    assert len({row["correlation_id"] for row in rows}) == 1
    assert rows[0]["correlation_id"] in done.stderr
    fingerprint = suite.key_fingerprint(stack["test_key"][1])
    for row in rows:
        assert row["format"] == "papaia.audit/1"
        assert row["detail"]["fingerprint"] == fingerprint
        assert row["detail"]["scope"] == "test"
        assert row["detail"]["core_version"] == PRE
        assert row["detail"]["bom_digest"].startswith("sha256:")
    # Keycloak and the runner of the admin steps, then the add-on's database and the
    # runner (whose client step the add-on start uses).
    assert done.stdout.count("2 image(s) verified") == checks
    # Nothing of the option is stored.
    for path in stack["config"].rglob("*"):
        if path.is_file() and path != stack["config"] / images.AUDIT_LOG:
            assert str(stack["anchor"]) not in path.read_text("utf-8", errors="replace")


# ── negative ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("command", ["restore", "restore-scoped"])
def test_the_runner_of_the_admin_steps_is_checked_under_the_anchor(tmp_path, candidate,
                                                                  command):
    """The runner image (docs/adr/0033) is part of the check the option reaches: unsigned,
    the restore stops before Keycloak starts."""
    stack = candidate
    journal._after_backup(stack)
    stack["registry"].write_bytes(pickle.dumps(_signed_registry(stack["test_key"], tmp_path)))

    done, calls = _restore(tmp_path, stack, command, f"--test-trust-anchor={stack['anchor']}")

    assert done.returncode == 3, done.stdout + done.stderr
    assert RUNNER in done.stderr
    assert not any(" up -d " in call for call in calls)
    assert f"'{command}' ended with exit code 3" in done.stderr



@pytest.mark.parametrize("command", ["restore", "restore-scoped"])
def test_a_release_version_refuses_the_option_before_anything_is_read(
    tmp_path, candidate, command
):
    stack = candidate
    journal._after_backup(stack)
    (stack["repo"] / "VERSION").write_text("1.10.0\n", encoding="ascii")

    done, calls = _restore(tmp_path, stack, command, f"--test-trust-anchor={stack['anchor']}")

    assert done.returncode == 2, done.stdout + done.stderr
    assert "is not a pre-release" in done.stderr
    assert "Nothing else was read." in done.stderr
    # Only the gate ran: no restore point read, no docker, no audit row.
    assert len(calls) == 1 and "test-anchor --phase=begin" in calls[0]
    assert (stack["config"] / "notes.txt").read_text() == "changed\n"
    assert _anchor_rows(stack["config"]) == []


@pytest.mark.parametrize("command", ["restore", "restore-scoped"])
def test_a_test_bill_without_the_option_still_stops_the_restore_with_exit_3(
    tmp_path, candidate, command
):
    stack = candidate
    journal._after_backup(stack)

    done, calls = _restore(tmp_path, stack, command)

    assert done.returncode == 3, done.stdout + done.stderr
    assert "no trust anchor" in done.stderr
    assert "Keycloak could not be started on its own; no module was started." in done.stderr
    assert not any(" up -d " in call for call in calls)
    assert "post-restore core now" not in calls
    assert "TEST TRUST ANCHOR" not in done.stderr
    assert _anchor_rows(stack["config"]) == []


@pytest.mark.parametrize("command", ["restore", "restore-scoped"])
def test_a_test_bill_signed_with_another_key_is_refused(tmp_path, candidate, command):
    stack = candidate
    journal._after_backup(stack)

    done, calls = _restore(tmp_path, stack, command,
                           f"--test-trust-anchor={stack['wrong_anchor']}")

    assert done.returncode == 3, done.stdout + done.stderr
    assert "fingerprint" in done.stderr
    assert not any(" up -d " in call for call in calls)
    rows = _anchor_rows(stack["config"])
    assert [(row["operation"], row["result"]) for row in rows] == [("restore", "denied")]
    assert rows[0]["detail"]["fingerprint"] == suite.key_fingerprint(stack["other_key"][1])
    assert f"'{command}' ended with exit code 3" in done.stderr


@pytest.mark.parametrize("command", ["restore", "restore-scoped"])
def test_a_delivery_bill_with_the_option_is_refused(tmp_path, candidate, command):
    stack = candidate
    journal._after_backup(stack)
    _write_bom(tmp_path, stack, scope="delivery")

    done, calls = _restore(tmp_path, stack, command, f"--test-trust-anchor={stack['anchor']}")

    assert done.returncode == 3, done.stdout + done.stderr
    assert "scope" in done.stderr
    assert not any(" up -d " in call for call in calls)
    rows = _anchor_rows(stack["config"])
    assert [(row["operation"], row["result"]) for row in rows] == [("restore", "denied")]


@pytest.mark.parametrize("command", ["restore", "restore-scoped"])
def test_neither_the_environment_nor_the_configuration_enables_the_anchor(
    tmp_path, candidate, command
):
    stack = candidate
    journal._after_backup(stack)
    anchor = str(stack["anchor"])
    with (stack["config"] / ".env").open("a", encoding="utf-8") as env:
        env.write(f"TEST_TRUST_ANCHOR={anchor}\nPAPAIA_TEST_TRUST_ANCHOR={anchor}\n")

    done, calls = _restore(tmp_path, stack, command,
                           env={"TEST_TRUST_ANCHOR": anchor, "PAPAIA_TEST_TRUST_ANCHOR": anchor})

    assert done.returncode == 3, done.stdout + done.stderr
    assert "no trust anchor" in done.stderr
    assert "TEST TRUST ANCHOR" not in done.stderr
    assert not any("--test-trust-anchor" in call for call in calls)
    assert _anchor_rows(stack["config"]) == []


def test_the_restore_entrypoint_runs_both_commands_through_the_gate():
    """papaia-ctl hands `restore` and `restore-scoped` to the commands this test runs."""
    ctl = (REPO / "tools" / "papaia-ctl").read_text("utf-8")
    assert "restore)       cmd_restore \"$@\" ;;" in ctl
    assert "restore-scoped) cmd_restore_scoped \"$@\" ;;" in ctl
    assert '_dispatch_with_test_anchor _dispatch "$cmd" "$@"' in ctl
