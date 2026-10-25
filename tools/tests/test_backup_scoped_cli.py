"""The bash half of a scoped backup, with `py_cli` and `docker` replaced by functions.

What is checked is what bash does with their answers: which exit status a refused selection
ends in, that nothing reaches Docker when it is, how the scope shows up in the output and the
log, and that a scoped restore tears an add-on down with the same project name, env files and
overrides as `addon stop`. The planning itself is covered by test_backup.py.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
BACKUP_SH = TOOLS / "lib" / "sh" / "backup.sh"
ADDON_SH = TOOLS / "lib" / "sh" / "addon.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")

_HARNESS = """
set -euo pipefail
CONFIG_DIR="@CONFIG@"
DEFAULT_CONFIG_DIR="@CONFIG@"
REPO_ROOT="@ROOT@"
COMPOSE_FILE="@ROOT@/src/docker-compose.yml"
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; }
success() { echo "OK: $*"; }
_require_setup_done() { :; }
py_cli() {
    echo "py_cli $*" >> "@LOG@"
    case "$1" in
        backup-dir) echo "@BACKUPS@" ;;
        addon-path) echo "@ADDON_PATH@" ;;
        addon-override-files) ;;
        *) @PY_CLI@ ;;
    esac
}
docker() {
    echo "docker $*" >> "@LOG@"
    case "$1" in
        volume|ps|inspect) ;;
    esac
}
source "@ADDON@"
source "@BACKUP@"
"""


def _run(tmp_path: Path, body: str, *, py_cli: str = "return 1") -> tuple[
    subprocess.CompletedProcess[str], list[str]
]:
    assert BASH is not None
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    (tmp_path / "backups").mkdir(exist_ok=True)
    harness = (
        _HARNESS.replace("@CONFIG@", (tmp_path / "config").as_posix())
        .replace("@ROOT@", (tmp_path / "root").as_posix())
        .replace("@LOG@", log.as_posix())
        .replace("@BACKUPS@", (tmp_path / "backups").as_posix())
        .replace("@ADDON_PATH@", (tmp_path / "addons" / "paperless").as_posix())
        .replace("@ADDON@", ADDON_SH.as_posix())
        .replace("@BACKUP@", BACKUP_SH.as_posix())
        .replace("@PY_CLI@", py_cli)
    )
    done = subprocess.run(
        [BASH, "-c", f"{harness}\n{body}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return done, log.read_text(encoding="utf-8").splitlines()


def test_a_selection_that_matches_nothing_exits_2_and_never_reaches_docker(
    tmp_path: Path,
) -> None:
    py_cli = 'if [ "$1" = backup-plan ]; then echo "ERROR: nothing to back up" >&2; return 2; fi'

    done, calls = _run(tmp_path, "cmd_backup --only=addon:ghost", py_cli=py_cli)

    assert done.returncode == 2
    assert "nothing to back up" in done.stderr
    assert any(c.startswith("py_cli backup-plan") and "--only=addon:ghost" in c for c in calls)
    assert not any(c.startswith("docker run") or c.startswith("docker pause") for c in calls)
    assert not any("backup-finish" in c for c in calls)
    assert not list((tmp_path / "backups").iterdir())


def test_an_empty_selection_is_refused_before_planning(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, "cmd_backup --only=")

    assert done.returncode == 2
    assert "at least one selector" in done.stderr
    assert not any(c.startswith("py_cli backup-plan") for c in calls)


def test_a_failure_to_plan_stays_exit_3(tmp_path: Path) -> None:
    py_cli = 'if [ "$1" = backup-plan ]; then return 3; fi'

    done, _ = _run(tmp_path, "cmd_backup --only=addon:paperless", py_cli=py_cli)

    assert done.returncode == 3
    assert "Could not plan the backup" in done.stderr


def test_a_scoped_backup_prints_its_id_like_a_full_one_and_logs_the_scope(
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "backups" / "2026-10-25_10-00-00"
    snapshot.mkdir(parents=True)
    data = tmp_path / "addons" / "paperless" / "data"
    data.mkdir(parents=True)
    py_cli = f"""
    case "$1" in
        backup-plan)
            printf 'SNAPSHOT\\t{snapshot.as_posix()}\\n'
            printf 'SCOPE\\taddon:paperless\\n'
            printf 'volume\\tvolumes/paperless_pgdata.tar.gz\\t'
            printf 'paperless_pgdata\\taddon:paperless\\n'
            printf 'binddir\\tbinds/paperless--data.tar.gz\\t{data.as_posix()}\\taddon:paperless\\n'
            ;;
        backup-finish)
            printf 'ID\\t2026-10-25_10-00-00\\nSIZE_MB\\t1.5\\nARTIFACTS\\t2\\n'
            ;;
    esac
    """

    done, calls = _run(tmp_path, "cmd_backup --only=addon:paperless", py_cli=py_cli)

    assert done.returncode == 0, done.stderr
    assert "Scope: addon:paperless" in done.stdout
    assert "OK: backup complete: 2026-10-25_10-00-00 (2 artifacts, 1.5 MB)" in done.stdout
    runs = [c for c in calls if c.startswith("docker run")]
    assert len(runs) == 2
    log = (tmp_path / "backups" / "backup.log").read_text(encoding="utf-8")
    assert "id=2026-10-25_10-00-00 result=ok" in log
    assert "scope=addon:paperless" in log


def test_a_backup_of_the_whole_stack_logs_no_scope(tmp_path: Path) -> None:
    snapshot = tmp_path / "backups" / "2026-10-25_11-00-00"
    snapshot.mkdir(parents=True)
    py_cli = f"""
    case "$1" in
        backup-plan) printf 'SNAPSHOT\\t{snapshot.as_posix()}\\n' ;;
        backup-finish) printf 'ID\\t2026-10-25_11-00-00\\nSIZE_MB\\t0.1\\nARTIFACTS\\t0\\n' ;;
    esac
    """

    done, calls = _run(tmp_path, "cmd_backup", py_cli=py_cli)

    assert done.returncode == 0, done.stderr
    assert not any("--only" in c for c in calls if c.startswith("py_cli backup-plan"))
    log = (tmp_path / "backups" / "backup.log").read_text(encoding="utf-8")
    assert "scope=" not in log


def test_restoring_a_scoped_point_as_a_whole_exits_2_without_touching_the_stack(
    tmp_path: Path,
) -> None:
    py_cli = (
        'if [ "$1" = restore-resolve ]; then echo "ERROR: only holds addon:paperless" >&2;'
        " return 2; fi"
    )

    done, calls = _run(tmp_path, "cmd_restore -y --restore-point=scoped", py_cli=py_cli)

    assert done.returncode == 2
    assert "only holds addon:paperless" in done.stderr
    assert "Could not resolve a restore point" not in done.stderr
    assert not any(c.startswith("docker ") for c in calls)


def test_the_scoped_teardown_goes_through_the_addon_compose_wrapper(tmp_path: Path) -> None:
    addon = tmp_path / "addons" / "paperless"
    addon.mkdir(parents=True)
    (addon / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (addon / ".env").write_text("A=1\n", encoding="utf-8")
    (tmp_path / "root" / "src").mkdir(parents=True)
    (tmp_path / "root" / "src" / ".env").write_text("PAPAIA_PROJECT=papaia\n", encoding="utf-8")

    done, calls = _run(tmp_path, '_restore_teardown_scoped "" "paperless"')

    assert done.returncode == 0, done.stderr
    downs = [c for c in calls if c.startswith("docker compose")]
    root = (tmp_path / "root").as_posix()
    assert downs == [
        f"docker compose -p paperless -f {addon.as_posix()}/docker-compose.yml"
        f" --env-file {root}/src/.env --env-file {addon.as_posix()}/.env down"
    ]
    assert "RESTORE-STEP\tteardown\taddon:paperless\tok" in done.stdout


def test_the_scoped_teardown_skips_an_addon_whose_files_are_gone(tmp_path: Path) -> None:
    done, calls = _run(tmp_path, '_restore_teardown_scoped "" "paperless"')

    assert done.returncode == 0, done.stderr
    assert not any(c.startswith("docker compose") for c in calls)
    assert "RESTORE-STEP\tteardown\taddon:paperless\tmissing" in done.stdout
