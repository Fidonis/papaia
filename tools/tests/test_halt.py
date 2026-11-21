"""The platform-wide emergency halt (PLT-61, OPS-20, KE-15; docs/halt.md).

`papaia-ctl halt set` writes `$PAPAIA_CONFIG_DIR/state/halt.json` on the host, without
Keycloak or any other service. Every service that acts mounts the folder read-only and
checks the file before each write, send or delete and every 5 s: the halt takes effect
within 10 s for writes, sends and deletes and within 60 s for everything else (Ä-39).
Lifting it needs a reason. Setting, lifting and a refused lift are `papaia.audit/1`
rows of the host account.

The propagation is measured with a stub module that guards its effects the way every
module does (lib/halt.HaltWatch), against the real `papaia-ctl` command.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest
import yaml

from lib import halt, render_core
from lib import realm_sync as rs
from tests.test_hosted_model import _setup

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
CTL = TOOLS / "papaia-ctl"
BACKUP_SH = TOOLS / "lib" / "sh" / "backup.sh"
HOOKS = REPO / "src" / "ai" / "litellm" / "papaia_hooks.py"
BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")

# OPS-20-A3 (authoritative for writes, sends and deletes after Ä-39) and PLT-61-A1.
WRITE_DEADLINE = 10.0
OTHER_DEADLINE = 60.0


def _seeded(path: Path) -> Path:
    """A configuration directory `_require_setup_done` accepts, single node."""
    path.mkdir(parents=True, exist_ok=True)
    (path / ".env").write_text("COMPOSE_PROJECT_NAME=papaia\n", encoding="utf-8")
    (path / "deployment.yaml").write_text("core: {}\n", encoding="utf-8")
    halt.ensure_dir(path)  # as `render` leaves it before the services start
    return path


def _ctl(config_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """The real papaia-ctl, with the interpreter of this test run first on PATH."""
    assert BASH is not None
    env = dict(os.environ)
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env.get('PATH', '')}"
    return subprocess.run(
        [BASH, str(CTL), "halt", *args, f"--config-dir={config_dir}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


def _rows(config_dir: Path) -> list[dict]:
    path = rs.audit_path(config_dir)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _doc(config_dir: Path) -> dict:
    return json.loads(halt.state_path(config_dir).read_text(encoding="utf-8"))


class StubModule:
    """A module that keeps acting: each effect (a write) is guarded by the halt check
    before it starts; a timer polls every POLL_SECONDS for the paths without an effect
    (the banner). Records when each effect started and when the banner went up."""

    def __init__(self, config_dir: Path, *, guard_effects: bool = True, pace: float = 0.02):
        self.watch = halt.HaltWatch(halt.state_path(config_dir))
        self.guard_effects = guard_effects
        self.pace = pace
        self.effects: list[float] = []
        self.refused = 0
        self.banner_since: float | None = None
        self._polled_halt = False
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._work, daemon=True),
            threading.Thread(target=self._timer, daemon=True),
        ]

    def __enter__(self) -> StubModule:
        for t in self._threads:
            t.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=10)

    def _work(self) -> None:
        while not self._stop.is_set():
            # An effect starts with its check; that is the time it is recorded under.
            started = time.monotonic()
            halted = self.watch.halted() if self.guard_effects else self._polled_halt
            if halted:
                self.refused += 1
            else:
                self.effects.append(started)
            time.sleep(self.pace)

    def _timer(self) -> None:
        while not self._stop.is_set():
            self._polled_halt = self.watch.poll().active
            if self._polled_halt and self.banner_since is None:
                self.banner_since = time.monotonic()
            self._stop.wait(halt.POLL_SECONDS)


# --- propagation -----------------------------------------------------------------------


@needs_bash
def test_a_host_halt_stops_every_write_of_a_stub_module_within_10_seconds(tmp_path):
    config_dir = _seeded(tmp_path / "config")
    with StubModule(config_dir) as module:
        time.sleep(0.3)
        assert module.effects, "the stub module did not act before the halt"
        done = _ctl(config_dir, "set", "--reason=exercise")
        returned = time.monotonic()
        assert done.returncode == 0, done.stderr
        time.sleep(1.0)
        last = max(module.effects)
        refused = module.refused
    # Measured from the return of the command to the last start of an effect.
    assert last - returned <= WRITE_DEADLINE
    assert refused > 0
    assert last <= returned  # a stat per effect: nothing starts after the command returned


@needs_bash
def test_the_timer_alone_raises_the_banner_within_60_and_stops_within_10_seconds(tmp_path):
    """A path that only follows the 5 s timer (no effect of its own to guard)."""
    config_dir = _seeded(tmp_path / "config")
    with StubModule(config_dir, guard_effects=False) as module:
        time.sleep(0.3)
        done = _ctl(config_dir, "set")
        returned = time.monotonic()
        assert done.returncode == 0, done.stderr
        deadline = returned + halt.POLL_SECONDS + 2
        while module.banner_since is None and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.2)
        last = max(module.effects)
        banner = module.banner_since
    assert banner is not None and banner - returned <= min(WRITE_DEADLINE, OTHER_DEADLINE)
    assert last - returned <= WRITE_DEADLINE


@needs_bash
def test_the_halt_outlasts_a_restart_and_needs_a_reason_to_be_lifted(tmp_path):
    config_dir = _seeded(tmp_path / "config")
    assert _ctl(config_dir, "set").returncode == 0
    # A restarted service starts with a new reader and finds the file on the host.
    assert halt.HaltWatch(halt.state_path(config_dir)).halted()

    refused = _ctl(config_dir, "clear")
    assert refused.returncode == 2
    assert "needs a reason" in refused.stderr
    assert halt.HaltWatch(halt.state_path(config_dir)).halted()

    lifted = _ctl(config_dir, "clear", "--reason", "drill finished")
    assert lifted.returncode == 0, lifted.stderr
    assert not halt.HaltWatch(halt.state_path(config_dir)).halted()
    assert _doc(config_dir)["reason"] == "drill finished"


@needs_bash
def test_on_and_off_are_set_and_clear_and_status_reports_the_state(tmp_path):
    config_dir = _seeded(tmp_path / "config")
    assert _ctl(config_dir, "on").returncode == 0
    status = _ctl(config_dir, "status", "--json")
    assert status.returncode == 0
    assert json.loads(status.stdout)["active"] is True
    assert _ctl(config_dir, "off", "--reason=ok").returncode == 0
    assert "not active" in _ctl(config_dir, "status").stdout


# --- the state file --------------------------------------------------------------------


def test_set_writes_the_documented_file_readable_for_the_services(tmp_path):
    config_dir = tmp_path / "config"
    changed, state = halt.set_halt(config_dir, "incident 42", now=lambda: 1_790_000_000.4)
    assert changed and state.active
    doc = _doc(config_dir)
    assert doc == {
        "active": True,
        "since": 1_790_000_000,
        "reason": "incident 42",
        "by": rs._host_account(),
    }
    assert doc["by"].startswith("host:")
    assert stat.S_IMODE(os.stat(halt.state_dir(config_dir)).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(halt.state_path(config_dir)).st_mode) == 0o644
    # Replaced by a rename: no partial file is ever left next to it.
    assert sorted(p.name for p in halt.state_dir(config_dir).iterdir()) == [
        halt.LOCK_FILE,
        halt.STATE_FILE,
    ]


def test_setting_an_active_halt_again_changes_nothing(tmp_path):
    config_dir = tmp_path / "config"
    halt.set_halt(config_dir, "first", now=lambda: 100.0)
    changed, state = halt.set_halt(config_dir, "second", now=lambda: 200.0)
    assert not changed
    assert (state.since, state.reason) == (100, "first")
    assert len(_rows(config_dir)) == 1


def test_lifting_an_inactive_halt_changes_nothing(tmp_path):
    config_dir = tmp_path / "config"
    changed, _ = halt.clear_halt(config_dir, "nothing to lift")
    assert not changed
    assert not halt.state_path(config_dir).exists()
    assert _rows(config_dir) == []


@pytest.mark.parametrize(
    "reason",
    ["", "   ", None],
)
def test_lifting_without_a_reason_is_refused_and_audited(tmp_path, reason):
    config_dir = tmp_path / "config"
    halt.set_halt(config_dir, None)
    with pytest.raises(halt.HaltError, match="needs a reason"):
        halt.clear_halt(config_dir, reason)
    assert _doc(config_dir)["active"] is True
    denied = _rows(config_dir)[-1]
    assert (denied["event"], denied["result"], denied["error_code"]) == (
        "emergency_stop_lifted",
        "denied",
        "reason_required",
    )


@pytest.mark.parametrize("reason", ["line\nbreak", "tab\there", "x" * 501])
def test_a_malformed_reason_is_refused_before_anything_changes(tmp_path, reason):
    config_dir = tmp_path / "config"
    with pytest.raises(halt.HaltError):
        halt.set_halt(config_dir, reason)
    assert not halt.state_path(config_dir).exists()
    assert _rows(config_dir) == []


def test_set_and_clear_are_audit_rows_of_the_host_without_the_reason(tmp_path):
    config_dir = tmp_path / "config"
    halt.set_halt(config_dir, "secret-looking text")
    halt.clear_halt(config_dir, "back to normal")
    rows = _rows(config_dir)
    assert [(r["event"], r["operation"], r["result"]) for r in rows] == [
        ("emergency_stop_set", "halt.set", "allowed"),
        ("emergency_stop_lifted", "halt.clear", "allowed"),
    ]
    for row in rows:
        assert row["format"] == "papaia.audit/1"
        assert row["writer"] == "papaia-ctl/halt"
        assert row["sub"].startswith("host:")
        assert row["identity_kind"] is None
        assert row["service_account"] is None
        assert row["azp"] is None
        assert row["effect"] == "write"
        assert row["object_ref"] == {"type": "platform_halt", "id": "platform"}
        assert row["correlation_id"]
        text = json.dumps(row)
        assert "secret-looking" not in text and "back to normal" not in text
    assert rows[0]["correlation_id"] != rows[1]["correlation_id"]
    assert [r["source_seq"] for r in rows] == [1, 2]


def test_setting_the_halt_does_not_wait_for_a_locked_audit_outbox(tmp_path, monkeypatch):
    """A running realm sync holds the outbox up to 120 s; the halt is in force before."""
    config_dir = tmp_path / "config"
    seen: list[bool] = []

    class Blocked:
        def __init__(self, *a, **k):
            seen.append(halt.read(halt.state_path(config_dir)).active)
            raise rs.RealmSyncError("another papaia-ctl run holds the outbox")

    monkeypatch.setattr(halt.rs, "AuditLog", Blocked)
    assert halt.main(config_dir, "set", None) == 1
    assert seen == [True]
    assert halt.read(halt.state_path(config_dir)).active


def test_lifting_the_halt_waits_for_its_audit_row(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    halt.set_halt(config_dir, None)

    def blocked(*a, **k):
        raise rs.RealmSyncError("another papaia-ctl run holds the outbox")

    monkeypatch.setattr(halt.rs, "AuditLog", blocked)
    assert halt.main(config_dir, "clear", "done") == 1
    assert halt.read(halt.state_path(config_dir)).active


# --- readers fail closed ---------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"{",
        b"[]",
        b'{"active": false}',
        b'{"active": false, "since": 1, "reason": "", "by": "host:x", "extra": 1}',
        b'{"active": "no", "since": 1, "reason": "", "by": "host:x"}',
        b'{"active": false, "since": -1, "reason": "", "by": "host:x"}',
        b'{"active": false, "since": true, "reason": "", "by": "host:x"}',
        b'{"active": false, "since": 1, "reason": "", "by": ""}',
        b'{"active": false, "since": 1, "reason": 3, "by": "host:x"}',
        b" " * 5000,
    ],
)
def test_an_unusable_file_counts_as_an_active_halt(tmp_path, content):
    folder = tmp_path / "state"
    folder.mkdir()
    (folder / "halt.json").write_bytes(content)
    state = halt.read(folder / "halt.json")
    assert state.active and state.problem


def test_no_file_is_no_halt_but_a_missing_folder_is(tmp_path):
    (tmp_path / "state").mkdir()
    assert not halt.read(tmp_path / "state" / "halt.json").active
    assert halt.read(tmp_path / "gone" / "halt.json").active


def test_a_symlink_in_place_of_the_file_counts_as_an_active_halt(tmp_path):
    folder = tmp_path / "state"
    folder.mkdir()
    (tmp_path / "elsewhere.json").write_text(
        '{"active": false, "since": 1, "reason": "", "by": "host:x"}'
    )
    (folder / "halt.json").symlink_to(tmp_path / "elsewhere.json")
    assert halt.read(folder / "halt.json").active


def test_the_watch_sees_a_replaced_file_without_waiting(tmp_path):
    config_dir = tmp_path / "config"
    watch = halt.HaltWatch(halt.state_path(config_dir))
    halt.ensure_dir(config_dir)
    assert not watch.halted()
    halt.set_halt(config_dir, None)
    assert watch.halted()
    halt.clear_halt(config_dir, "ok")
    assert not watch.halted()


def test_status_of_an_unusable_file_says_active(tmp_path, capsys):
    config_dir = tmp_path / "config"
    halt.ensure_dir(config_dir)
    halt.state_path(config_dir).write_text("garbage")
    assert halt.main(config_dir, "status", None, as_json=True) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["active"] is True and "problem" in out


# --- the command -----------------------------------------------------------------------


@needs_bash
def test_the_command_is_dispatched_and_documented():
    text = CTL.read_text(encoding="utf-8")
    assert 'halt)          cmd_halt "$@" ;;' in text
    help_text = subprocess.run(
        [BASH, str(CTL), "help"], capture_output=True, text=True, timeout=60, check=False
    ).stdout
    assert "papaia-ctl halt set      [--reason=TEXT] [--config-dir=PATH]" in help_text
    assert "papaia-ctl halt clear    --reason=TEXT [--config-dir=PATH]" in help_text
    assert "papaia-ctl halt status   [--json] [--config-dir=PATH]" in help_text
    # The usage range still ends with the header block.
    assert "--resume-from=X.Y.Z" in help_text


@needs_bash
def test_the_command_refuses_unknown_input(tmp_path):
    config_dir = _seeded(tmp_path / "config")
    for args, message in [
        (("pause",), "Unknown 'halt' subcommand: 'pause'"),
        (("set", "--bogus"), "Unknown option for halt set: --bogus"),
        (("set", "--json"), "--json is an option of 'halt status' only"),
        (("status", "--reason=x"), "--reason is an option of 'halt set' and 'halt clear'"),
    ]:
        done = _ctl(config_dir, *args)
        assert done.returncode == 2, args
        assert message in done.stderr, done.stderr
    assert not halt.state_path(config_dir).exists()


@needs_bash
def test_the_command_needs_a_setup_and_a_single_node(tmp_path):
    assert _ctl(tmp_path / "none", "set").returncode == 2
    config_dir = _seeded(tmp_path / "config")
    (config_dir / "deployment.yaml").write_text("topology:\n  mode: distributed\n")
    done = _ctl(config_dir, "set")
    assert done.returncode != 0
    assert not halt.state_path(config_dir).exists()


# --- wiring in the core ----------------------------------------------------------------


def test_render_makes_the_halt_folder_compose_must_not_create(repo_root, config_dir):
    _setup(repo_root, config_dir)
    assert not halt.state_dir(config_dir).exists()
    render_core.render(config_dir, repo_root)
    halt_dir = halt.state_dir(config_dir)
    assert halt_dir.is_dir()
    assert stat.S_IMODE(os.stat(halt_dir).st_mode) == 0o755
    assert not halt.state_path(config_dir).exists()


def test_litellm_mounts_the_halt_folder_read_only_and_registers_the_hook():
    compose = yaml.safe_load((REPO / "src/ai/litellm/docker-compose.yml").read_text())
    mounts = [
        m for m in compose["services"]["litellm"]["volumes"]
        if isinstance(m, dict) and m.get("target") == "/run/papaia-halt"
    ]
    assert mounts == [
        {
            "type": "bind",
            "source": "${PAPAIA_CONFIG_DIR}/state",
            "target": "/run/papaia-halt",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    config = yaml.safe_load((REPO / "src/ai/litellm/config.yaml").read_text())
    assert "papaia_hooks.papaia_platform_halt" in config["litellm_settings"]["callbacks"]


@pytest.fixture
def hooks(monkeypatch):
    """papaia_hooks with stand-ins for the two LiteLLM and FastAPI names it uses."""

    class CustomLogger:
        def __init__(self, *a, **k):
            pass

    class HTTPException(Exception):
        def __init__(self, status_code, detail=None):
            super().__init__(status_code)
            self.status_code, self.detail = status_code, detail

    stubs = {
        "litellm": types.ModuleType("litellm"),
        "litellm.integrations": types.ModuleType("litellm.integrations"),
        "litellm.integrations.custom_logger": types.ModuleType("custom_logger"),
        "fastapi": types.ModuleType("fastapi"),
    }
    stubs["litellm.integrations.custom_logger"].CustomLogger = CustomLogger
    stubs["fastapi"].HTTPException = HTTPException
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)
    # Loaded from the source tree: no bytecode next to it.
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    spec = importlib.util.spec_from_file_location("papaia_hooks_under_test", HOOKS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HTTPException = HTTPException
    return module


def _call(hook, data=None):
    return asyncio.run(hook.async_pre_call_hook(None, None, data or {"model": "m"}, "completion"))


def test_the_model_gateway_refuses_every_request_while_the_halt_is_active(tmp_path, hooks):
    config_dir = tmp_path / "config"
    halt.ensure_dir(config_dir)
    hook = hooks._PlatformHalt(str(halt.state_path(config_dir)))
    assert _call(hook, {"model": "m"}) == {"model": "m"}

    halt.set_halt(config_dir, None)
    with pytest.raises(hooks.HTTPException) as refused:
        _call(hook)
    assert refused.value.status_code == 503
    assert refused.value.detail["error"]["code"] == "platform_halt"
    assert "Not-Halt" in refused.value.detail["error"]["message"]

    halt.clear_halt(config_dir, "ok")
    assert _call(hook) == {"model": "m"}


def test_the_model_gateway_fails_closed_without_its_mount(tmp_path, hooks):
    hook = hooks._PlatformHalt(str(tmp_path / "not-mounted" / "halt.json"))
    with pytest.raises(hooks.HTTPException):
        _call(hook)


@pytest.mark.parametrize(
    "content",
    [
        b"{",
        b'{"active": false}',
        b'{"active": "false", "since": 1, "reason": "", "by": "host:x"}',
        b'{"active": false, "since": 1, "reason": "", "by": "host:x", "x": 1}',
        b'{"active": false, "since": 1, "reason": "", "by": "host:x"}',
        b'{"active": true, "since": 1, "reason": "", "by": "host:x"}',
    ],
)
def test_the_model_gateway_reads_the_file_as_the_core_does(tmp_path, hooks, content):
    (tmp_path / "halt.json").write_bytes(content)
    assert hooks.halt_active(content) == halt.parse(content).active


# --- backup and restore ----------------------------------------------------------------


def test_the_backup_of_the_config_dir_leaves_the_halt_out():
    text = BACKUP_SH.read_text(encoding="utf-8")
    assert "--exclude=./state)" in text


def _unpack_script() -> str:
    """The restore step as backup.sh hands it to the container, rooted in a test folder."""
    assert BASH is not None
    out = subprocess.run(
        [BASH, "-c", f'set -euo pipefail\nsource "{BACKUP_SH}"\nprintf %s "$_RESTORE_UNPACK"'],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout
    assert out
    return out


@needs_bash
def test_a_restore_keeps_the_halt_of_the_host(tmp_path):
    """Runs the unpack step with a local shell and tar in place of the backup image."""
    if shutil.which("tar") is None:
        pytest.skip("tar is not available")
    root = tmp_path / "t"
    source = tmp_path / "src"
    (source / "state").mkdir(parents=True)
    (source / "state" / "halt.json").write_text("old")
    (source / ".env").write_text("RESTORED=1\n")
    backup = tmp_path / "backup"
    backup.mkdir()
    subprocess.run(
        ["tar", "czf", str(backup / "configdir.tgz"), "-C", str(source), "."], check=True
    )
    (root / "state").mkdir(parents=True)
    (root / "state" / "halt.json").write_text("current")
    (root / "stale").write_text("x")
    (root / ".hidden").write_text("x")
    script = (
        _unpack_script().replace("/target", str(root)).replace("/backup", str(backup))
    )
    subprocess.run(
        ["sh", "-c", script],
        check=True,
        env={**os.environ, "ARCHIVE": "configdir.tgz", "KEEP": "state"},
        timeout=30,
    )
    assert (root / "state" / "halt.json").read_text() == "current"
    assert (root / ".env").read_text() == "RESTORED=1\n"
    assert not (root / "stale").exists() and not (root / ".hidden").exists()
